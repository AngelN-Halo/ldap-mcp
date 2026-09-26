import csv
import html
import json
import os
import re
import ssl
import xml.etree.ElementTree as ET
from io import StringIO
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP
from ldap3 import BASE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException


load_dotenv()

mcp = FastMCP("idm-edirectory-readonly")

DEFAULT_USER_ATTRIBUTES = ["cn", "sn", "uid", "mail"]
EXTENDED_USER_ATTRIBUTES = [
    "cn",
    "sn",
    "givenName",
    "uid",
    "mail",
    "employeeNumber",
    "isdWorkforceId",
    "objectClass",
    "loginDisabled",
]
SAFE_OBJECT_ATTRIBUTES = ["cn", "objectClass", "description", "owner", "member", "uniqueMember"]
SECURITY_ATTRIBUTES = ["groupMembership", "securityEquals", "equivalentToMe", "ACL"]
REFERENCE_ATTRIBUTES = [
    "cn",
    "uid",
    "mail",
    "objectClass",
    "securityEquals",
    "groupMembership",
    "memberOf",
]
ISD_USER_ATTRIBUTES = [
    "cn",
    "uid",
    "mail",
    "givenName",
    "sn",
    "isdPreferredGivenName",
    "isdPreferredSurname",
    "employeeNumber",
    "isdWorkforceId",
    "isdManagerWorkforceId",
    "employeeType",
    "isdEmploymentStatus",
    "isdSiteCode",
    "isdPreviousSiteCode",
    "ou",
    "isdJobCategory",
    "isdPositionCode",
    "isdAssignmentClass",
    "isdBadgeId",
    "loginDisabled",
    "DirXML-ADContext",
]
ISD_MEMBERSHIP_ATTRIBUTES = ["nrfDynamicGroupMembership", "nrfMemberOf"]
CSV_USER_ATTRIBUTES = [
    "cn",
    "givenName",
    "sn",
    "isdPreferredGivenName",
    "isdPreferredSurname",
    "mail",
    "isdWorkforceId",
    "employeeType",
    "isdEmploymentStatus",
    "isdSiteCode",
    "isdPreviousSiteCode",
    "ou",
    "isdJobCategory",
    "isdPositionCode",
    "isdAssignmentClass",
    "loginDisabled",
]
ISD_ENTITLEMENT_ATTRIBUTES = [
    "cn",
    "uid",
    "mail",
    "isdWorkforceId",
    "DirXML-EntitlementRef",
    "DirXML-EntitlementResult",
    "DirXML-Associations",
    "nrfDynamicGroupMembership",
    "nrfMemberOf",
    "nrfGroupRoles",
    "securityEquals",
]
ISD_ROLE_ATTRIBUTES = [
    "cn",
    "description",
    "objectClass",
    "member",
    "uniqueMember",
    "owner",
]
ISD_QUERYABLE_USER_ATTRIBUTES = {
    "cn",
    "uid",
    "mail",
    "sn",
    "givenName",
    "isdPreferredGivenName",
    "isdPreferredSurname",
    "employeeNumber",
    "isdWorkforceId",
    "isdManagerWorkforceId",
    "employeeType",
    "isdEmploymentStatus",
    "isdSiteCode",
    "isdPreviousSiteCode",
    "ou",
    "isdJobCategory",
    "isdPositionCode",
    "isdAssignmentClass",
    "isdBadgeId",
    "loginDisabled",
    "DirXML-ADContext",
}


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _config() -> dict[str, Any]:
    return {
        "host": os.getenv("IDM_LDAP_HOST", "192.0.2.10"),
        "port": _env_int("IDM_LDAP_PORT", 636),
        "use_ssl": _env_bool("IDM_LDAP_USE_SSL", True),
        "bind_dn": os.getenv("IDM_BIND_DN", ""),
        "bind_password": os.getenv("IDM_BIND_PASSWORD", ""),
        "search_base": os.getenv("IDM_SEARCH_BASE", "o=example"),
        "user_filter": os.getenv("IDM_USER_FILTER", "(objectClass=inetOrgPerson)"),
        "tls_validate": _env_bool("IDM_TLS_VALIDATE", True),
        "ca_cert_file": os.getenv("IDM_CA_CERT_FILE", ""),
        "default_limit": _env_int("IDM_DEFAULT_LIMIT", 50),
        "max_limit": _env_int("IDM_MAX_LIMIT", 500),
        "export_default_limit": _env_int("IDM_EXPORT_DEFAULT_LIMIT", 60000),
        "export_max_limit": _env_int("IDM_EXPORT_MAX_LIMIT", 100000),
    }


def escape_ldap_filter_value(value: str) -> str:
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    return "".join(replacements.get(char, char) for char in str(value))


def _clamp_limit(limit: int | None, default: int, maximum: int) -> int:
    if limit is None:
        return default
    try:
        requested = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(requested, maximum))


def _tls(config: dict[str, Any]) -> Tls:
    validate = ssl.CERT_REQUIRED if config["tls_validate"] else ssl.CERT_NONE
    kwargs: dict[str, Any] = {
        "validate": validate,
        "version": ssl.PROTOCOL_TLS_CLIENT,
    }
    if config["ca_cert_file"]:
        kwargs["ca_certs_file"] = config["ca_cert_file"]
    return Tls(**kwargs)


def _connect() -> Connection:
    config = _config()
    if not config["bind_dn"] or not config["bind_password"]:
        raise ValueError("IDM_BIND_DN and IDM_BIND_PASSWORD are required")

    server = Server(
        config["host"],
        port=config["port"],
        use_ssl=config["use_ssl"],
        tls=_tls(config),
        get_info="ALL",
    )
    return Connection(
        server,
        user=config["bind_dn"],
        password=config["bind_password"],
        auto_bind=True,
        raise_exceptions=True,
        receive_timeout=30,
    )


def _json_value(value: Any) -> Any:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _entry_to_dict(entry: Any) -> dict[str, Any]:
    return _attributes_to_dict(entry.entry_dn, entry.entry_attributes_as_dict)


def _attributes_to_dict(dn: str, attributes: dict[str, Any]) -> dict[str, Any]:
    item: dict[str, Any] = {"dn": dn}
    for attr, value in attributes.items():
        if isinstance(value, list):
            values = [_json_value(v) for v in value]
            item[attr] = values[0] if len(values) == 1 else values
        else:
            item[attr] = _json_value(value)
    return item


def _response_to_dict(response: dict[str, Any]) -> dict[str, Any]:
    return _attributes_to_dict(
        response.get("dn", ""),
        response.get("attributes", {}) or {},
    )


def _error(error: Exception) -> dict[str, Any]:
    return {"ok": False, "error": str(error)}


def _search(
    search_base: str,
    search_filter: str,
    attributes: list[str],
    limit: int,
    search_scope: str = SUBTREE,
) -> dict[str, Any]:
    try:
        with _connect() as conn:
            entries: list[dict[str, Any]] = []
            if search_scope == BASE or limit <= 1000:
                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    size_limit=limit,
                )
                entries = [_entry_to_dict(entry) for entry in conn.entries]
            else:
                responses = conn.extend.standard.paged_search(
                    search_base=search_base,
                    search_filter=search_filter,
                    search_scope=search_scope,
                    attributes=attributes,
                    paged_size=1000,
                    generator=True,
                )
                for response in responses:
                    if response.get("type") != "searchResEntry":
                        continue
                    entries.append(_response_to_dict(response))
                    if len(entries) >= limit:
                        break

            return {
                "ok": True,
                "count": len(entries),
                "limit": limit,
                "search_base": search_base,
                "filter": search_filter,
                "entries": entries,
            }
    except (LDAPException, ValueError) as exc:
        return _error(exc)



def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _parse_json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def _xml_text(root: ET.Element, path: str) -> str | None:
    found = root.find(path)
    return found.text if found is not None else None


def _parse_xml_fragment(value: str) -> ET.Element | None:
    try:
        return ET.fromstring(value.strip())
    except ET.ParseError:
        try:
            return ET.fromstring(html.unescape(value).strip())
        except ET.ParseError:
            return None


def _parse_entitlement_ref(value: str) -> dict[str, Any]:
    parts = value.split("#", 2)
    parsed: dict[str, Any] = {"raw": value}
    if len(parts) == 3:
        parsed.update({"dn": parts[0], "state": parts[1], "xml": parts[2]})
    else:
        parsed["xml"] = value

    root = _parse_xml_fragment(parsed.get("xml", ""))
    if root is not None:
        param_text = _xml_text(root, "param") or ""
        parsed.update({
            "src": _xml_text(root, "src"),
            "id": _xml_text(root, "id"),
            "param": _parse_json_object(param_text),
        })
    return parsed


def _parse_entitlement_result(value: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {"raw": value}
    root = _parse_xml_fragment(value)
    if root is not None:
        param_text = _xml_text(root, "param") or ""
        parsed.update({
            "dn": _xml_text(root, "dn"),
            "src": _xml_text(root, "src"),
            "state": _xml_text(root, "state"),
            "status": _xml_text(root, "status"),
            "message": _xml_text(root, "msg"),
            "timestamp": _xml_text(root, "timestamp"),
            "param": _parse_json_object(param_text),
        })
    return parsed


def _parse_role_assignment(value: str) -> dict[str, Any]:
    parts = value.split("#", 2)
    parsed: dict[str, Any] = {"raw": value}
    if len(parts) == 3:
        parsed.update({"role_dn": parts[0], "state": parts[1], "xml": parts[2]})
    else:
        parsed["xml"] = value

    root = _parse_xml_fragment(parsed.get("xml", ""))
    if root is not None:
        parsed.update({
            "start_time": _xml_text(root, "start_tm"),
            "request_time": _xml_text(root, "req_tm"),
            "instance_guid": _xml_text(root, "inst-guid"),
            "requester": _xml_text(root, "req"),
            "request_description": _xml_text(root, "req_desc"),
            "entitlement_dn": _xml_text(root, "ent-dn"),
            "cause_type": _xml_text(root, "cause/type"),
            "cause_group": _xml_text(root, "cause/group"),
        })
        ent_ref = _xml_text(root, "ent-ref")
        if ent_ref:
            parsed["entitlement_ref"] = _parse_entitlement_ref(html.unescape(ent_ref))
        parameter = root.find("parameter/value")
        if parameter is not None:
            parsed["parameter_key"] = parameter.attrib.get("parm-key")
            parsed["parameter"] = _parse_json_object(parameter.text or "")
    return parsed


def _parse_association(value: str) -> dict[str, Any]:
    parts = value.split("#", 2)
    if len(parts) == 3:
        return {"driver_dn": parts[0], "state": parts[1], "association_id": parts[2], "raw": value}
    return {"raw": value}


def _summarize_isd_user(
    user: dict[str, Any],
    include_entitlements: bool = False,
    include_memberships: bool = False,
) -> dict[str, Any]:
    summary = {key: user[key] for key in ISD_USER_ATTRIBUTES if key in user}
    if include_memberships:
        summary.update({key: user[key] for key in ISD_MEMBERSHIP_ATTRIBUTES if key in user})
    summary["dn"] = user.get("dn")
    if include_entitlements:
        summary["entitlements"] = _build_entitlement_summary(user)
    return summary


def _display_name(user: dict[str, Any]) -> str:
    first = user.get("isdPreferredGivenName") or user.get("givenName")
    last = user.get("isdPreferredSurname") or user.get("sn")
    if first and last:
        return f"{first} {last}"
    if user.get("cn"):
        return str(user["cn"]).replace("_", " ")
    return ""


def _build_entitlement_summary(user: dict[str, Any], include_raw: bool = False) -> dict[str, Any]:
    refs = [_parse_entitlement_ref(v) for v in _as_list(user.get("DirXML-EntitlementRef"))]
    results = [_parse_entitlement_result(v) for v in _as_list(user.get("DirXML-EntitlementResult"))]
    role_assignments = [_parse_role_assignment(v) for v in _as_list(user.get("nrfGroupRoles"))]
    associations = [_parse_association(v) for v in _as_list(user.get("DirXML-Associations"))]
    if not include_raw:
        for collection in (refs, results, role_assignments, associations):
            for item in collection:
                item.pop("raw", None)
                item.pop("xml", None)
    return {
        "entitlement_refs": refs,
        "entitlement_results": results,
        "role_assignments": role_assignments,
        "associations": associations,
        "dynamic_groups": _as_list(user.get("nrfDynamicGroupMembership")),
        "roles": _as_list(user.get("nrfMemberOf")),
        "security_equals": _as_list(user.get("securityEquals")),
    }




def _cn_from_dn(dn: str) -> str | None:
    match = re.match(r"cn=([^,]+)", dn, flags=re.IGNORECASE)
    return match.group(1) if match else None

def _value_contains(value: Any, query: str) -> bool:
    needle = query.casefold()
    if isinstance(value, dict):
        return any(_value_contains(v, query) for v in value.values())
    if isinstance(value, list):
        return any(_value_contains(v, query) for v in value)
    return needle in str(value).casefold()

def _identity_filter(value: str) -> str:
    escaped = escape_ldap_filter_value(value)
    return (
        "(&(objectClass=inetOrgPerson)"
        f"(|(uid={escaped})(mail={escaped})(cn={escaped})(sn={escaped})"
        f"(isdPreferredSurname={escaped})(employeeNumber={escaped})(isdWorkforceId={escaped})))"
    )


def _contains_filter(attribute: str, value: str) -> str:
    return f"({attribute}=*{escape_ldap_filter_value(value)}*)"


def _user_attrs(include_extended_attributes: bool) -> list[str]:
    return EXTENDED_USER_ATTRIBUTES if include_extended_attributes else DEFAULT_USER_ATTRIBUTES


@mcp.tool
def idm_health_check() -> dict[str, Any]:
    """Verify LDAPS connectivity and successful bind."""
    config = _config()
    try:
        with _connect() as conn:
            server_info = str(conn.server.info) if conn.server.info else ""
            if len(server_info) > 4000:
                server_info = server_info[:4000] + "...[truncated]"
            return {
                "ok": True,
                "host": config["host"],
                "port": config["port"],
                "use_ssl": config["use_ssl"],
                "search_base": config["search_base"],
                "tls_validate": config["tls_validate"],
                "server_info": server_info,
            }
    except (LDAPException, ValueError) as exc:
        return {
            "ok": False,
            "host": config["host"],
            "port": config["port"],
            "use_ssl": config["use_ssl"],
            "search_base": config["search_base"],
            "tls_validate": config["tls_validate"],
            "error": str(exc),
        }


@mcp.tool
def idm_search_users(
    query: str | None = None,
    limit: int | None = None,
    include_extended_attributes: bool = False,
) -> dict[str, Any]:
    """Search users by cn, sn, uid, or mail."""
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    if query is None or str(query).strip() == "":
        search_filter = config["user_filter"]
    else:
        escaped = escape_ldap_filter_value(str(query).strip())
        search_filter = (
            "(&(objectClass=inetOrgPerson)"
            f"(|(cn=*{escaped}*)(sn=*{escaped}*)(uid=*{escaped}*)(mail=*{escaped}*)))"
        )
    result = _search(
        config["search_base"],
        search_filter,
        _user_attrs(include_extended_attributes),
        result_limit,
    )
    if result.get("ok"):
        result["users"] = result.pop("entries")
    return result


@mcp.tool
def idm_get_user_by_uid(uid: str, include_extended_attributes: bool = True) -> dict[str, Any]:
    """Get a user by exact uid."""
    config = _config()
    escaped = escape_ldap_filter_value(uid)
    result = _search(
        config["search_base"],
        f"(&(objectClass=inetOrgPerson)(uid={escaped}))",
        _user_attrs(include_extended_attributes),
        2,
    )
    if result.get("ok"):
        entries = result.pop("entries")
        result["user"] = entries[0] if entries else None
        result["count"] = len(entries)
    return result


@mcp.tool
def idm_get_user_by_mail(mail: str, include_extended_attributes: bool = True) -> dict[str, Any]:
    """Get a user by exact mail address."""
    config = _config()
    escaped = escape_ldap_filter_value(mail)
    result = _search(
        config["search_base"],
        f"(&(objectClass=inetOrgPerson)(mail={escaped}))",
        _user_attrs(include_extended_attributes),
        2,
    )
    if result.get("ok"):
        entries = result.pop("entries")
        result["user"] = entries[0] if entries else None
        result["count"] = len(entries)
    return result


@mcp.tool
def idm_find_identity(value: str, include_extended_attributes: bool = True) -> dict[str, Any]:
    """Find an identity by uid, mail, cn, sn, employeeNumber, or isdWorkforceId."""
    config = _config()
    escaped = escape_ldap_filter_value(value)
    search_filter = (
        "(&(objectClass=inetOrgPerson)"
        f"(|(uid={escaped})(mail={escaped})(cn={escaped})(sn={escaped})"
        f"(employeeNumber={escaped})(isdWorkforceId={escaped})))"
    )
    result = _search(
        config["search_base"],
        search_filter,
        _user_attrs(include_extended_attributes),
        config["max_limit"],
    )
    if result.get("ok"):
        result["users"] = result.pop("entries")
    return result


@mcp.tool
def idm_find_disabled_users(
    limit: int | None = None,
    include_isd_attributes: bool = True,
) -> dict[str, Any]:
    """Find IDM users whose eDirectory login is disabled using loginDisabled=TRUE."""
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    attrs = ISD_USER_ATTRIBUTES if include_isd_attributes else EXTENDED_USER_ATTRIBUTES
    search_filter = "(&(objectClass=inetOrgPerson)(loginDisabled=TRUE))"
    result = _search(config["search_base"], search_filter, attrs, result_limit)
    if result.get("ok"):
        result["users"] = result.pop("entries")
    return result


@mcp.tool
def idm_export_users(
    limit: int | None = None,
    include_extended_attributes: bool = False,
    allow_large_export: bool = False,
) -> dict[str, Any]:
    """Export users for downstream comparison/reporting. Requires allow_large_export=true above 500 rows."""
    config = _config()
    default_limit = 500 if not allow_large_export else config["export_default_limit"]
    maximum = config["export_max_limit"] if allow_large_export else 500
    result_limit = _clamp_limit(limit, default_limit, maximum)
    requested = config["export_default_limit"] if limit is None else limit
    if not allow_large_export and int(requested) > 500:
        return {
            "ok": False,
            "error": "Large exports are guarded to avoid flooding chat context. Use a narrower lookup tool, set limit<=500, or explicitly set allow_large_export=true for reporting/export workflows.",
            "requested_limit": requested,
            "max_without_allow_large_export": 500,
        }
    result = _search(
        config["search_base"],
        config["user_filter"],
        _user_attrs(include_extended_attributes),
        result_limit,
    )
    if result.get("ok"):
        result["users"] = result.pop("entries")
    return result


def _isd_user_filter(
    query: str | None = None,
    site_code: str | None = None,
    previous_site_code: str | None = None,
    employee_type: str | None = None,
    employee_status: str | None = None,
    job_category: str | None = None,
    position_code: str | None = None,
    assignment_class: str | None = None,
    department: str | None = None,
    login_disabled: bool | None = None,
    require_mail: bool = False,
) -> str:
    filters = ["(objectClass=inetOrgPerson)"]
    if require_mail:
        filters.append("(mail=*)")
    if query and str(query).strip():
        q = str(query).strip()
        filters.append(
            "(|"
            f"{_contains_filter('cn', q)}"
            f"{_contains_filter('uid', q)}"
            f"{_contains_filter('mail', q)}"
            f"{_contains_filter('sn', q)}"
            f"{_contains_filter('isdPreferredSurname', q)}"
            f"{_contains_filter('isdPreferredGivenName', q)}"
            f"{_contains_filter('givenName', q)}"
            f"{_contains_filter('employeeNumber', q)}"
            f"{_contains_filter('isdWorkforceId', q)}"
            f"{_contains_filter('isdBadgeId', q)}"
            f"{_contains_filter('DirXML-ADContext', q)}"
            ")"
        )
    exact_filters = {
        "isdSiteCode": site_code,
        "isdPreviousSiteCode": previous_site_code,
        "employeeType": employee_type,
        "isdEmploymentStatus": employee_status,
        "isdJobCategory": job_category,
        "isdPositionCode": position_code,
        "isdAssignmentClass": assignment_class,
    }
    for attr, value in exact_filters.items():
        if value and str(value).strip():
            filters.append(f"({attr}={escape_ldap_filter_value(str(value).strip())})")
    if department and str(department).strip():
        filters.append(_contains_filter("ou", str(department).strip()))
    if login_disabled is not None:
        filters.append(f"(loginDisabled={'TRUE' if login_disabled else 'FALSE'})")
    return f"(&{''.join(filters)})"


def _csv_row_for_isd_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "Name": _display_name(user),
        "Email": user.get("mail") or "",
        "ExternalPersonId": user.get("isdWorkforceId") or "",
        "EmployeeType": user.get("employeeType") or "",
        "EmploymentStatus": user.get("isdEmploymentStatus") or "",
        "SiteCode": user.get("isdSiteCode") or "",
        "PreviousSiteCode": user.get("isdPreviousSiteCode") or "",
        "Department": user.get("ou") or "",
        "JobCategory": user.get("isdJobCategory") or "",
        "PositionCode": user.get("isdPositionCode") or "",
        "AssignmentClass": user.get("isdAssignmentClass") or "",
        "LoginDisabled": user.get("loginDisabled") if user.get("loginDisabled") != [] else "",
    }


@mcp.tool
def idm_export_active_users_csv(
    status: str = "A",
    limit: int | None = None,
    include_header: bool = True,
    allow_large_export: bool = True,
) -> dict[str, Any]:
    """Return a minimal CSV of users by illustrative employment status with only Name and Email columns."""
    config = _config()
    if not allow_large_export:
        result_limit = _clamp_limit(limit, 500, 500)
    else:
        result_limit = _clamp_limit(limit, config["export_default_limit"], config["export_max_limit"])
    escaped_status = escape_ldap_filter_value(status.strip())
    search_filter = f"(&(objectClass=inetOrgPerson)(isdEmploymentStatus={escaped_status})(mail=*))"
    result = _search(config["search_base"], search_filter, CSV_USER_ATTRIBUTES, result_limit)
    if not result.get("ok"):
        return result

    output = StringIO()
    writer = csv.writer(output, lineterminator="\n")
    if include_header:
        writer.writerow(["Name", "Email"])
    rows = []
    for user in result.pop("entries"):
        name = _display_name(user)
        email = user.get("mail")
        if not email:
            continue
        writer.writerow([name, email])
        rows.append({"name": name, "email": email})

    return {
        "ok": True,
        "count": len(rows),
        "limit": result_limit,
        "search_base": config["search_base"],
        "filter": search_filter,
        "columns": ["Name", "Email"],
        "csv": output.getvalue(),
        "preview": rows[:10],
    }



@mcp.tool
def idm_export_isd_users_csv(
    query: str | None = None,
    site_code: str | None = None,
    previous_site_code: str | None = None,
    employee_type: str | None = None,
    employee_status: str | None = None,
    job_category: str | None = None,
    position_code: str | None = None,
    assignment_class: str | None = None,
    department: str | None = None,
    login_disabled: bool | None = None,
    limit: int | None = None,
    include_header: bool = True,
    allow_large_export: bool = True,
) -> dict[str, Any]:
    """Return a minimal CSV report of ISD example users filtered by site, previous site, job, status, type, department, or login state."""
    config = _config()
    if not allow_large_export:
        result_limit = _clamp_limit(limit, 500, 500)
    else:
        result_limit = _clamp_limit(limit, config["export_default_limit"], config["export_max_limit"])
    search_filter = _isd_user_filter(
        query=query,
        site_code=site_code,
        previous_site_code=previous_site_code,
        employee_type=employee_type,
        employee_status=employee_status,
        job_category=job_category,
        position_code=position_code,
        assignment_class=assignment_class,
        department=department,
        login_disabled=login_disabled,
        require_mail=False,
    )
    result = _search(config["search_base"], search_filter, CSV_USER_ATTRIBUTES, result_limit)
    if not result.get("ok"):
        return result

    columns = [
        "Name",
        "Email",
        "ExternalPersonId",
        "EmployeeType",
        "EmploymentStatus",
        "SiteCode",
        "PreviousSiteCode",
        "Department",
        "JobCategory",
        "PositionCode",
        "AssignmentClass",
        "LoginDisabled",
    ]
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
    if include_header:
        writer.writeheader()
    rows = [_csv_row_for_isd_user(user) for user in result.pop("entries")]
    writer.writerows(rows)

    return {
        "ok": True,
        "count": len(rows),
        "limit": result_limit,
        "search_base": config["search_base"],
        "filter": search_filter,
        "columns": columns,
        "csv": output.getvalue(),
        "preview": rows[:10],
    }


@mcp.tool
def idm_get_object_by_dn(
    dn: str,
    include_security_attributes: bool = False,
) -> dict[str, Any]:
    """Inspect a specific LDAP object by DN using base/object scope."""
    attrs = SAFE_OBJECT_ATTRIBUTES + (SECURITY_ATTRIBUTES if include_security_attributes else [])
    result = _search(
        dn,
        "(objectClass=*)",
        attrs,
        1,
        search_scope=BASE,
    )
    if result.get("ok"):
        entries = result.pop("entries")
        result["object"] = entries[0] if entries else None
        result["count"] = len(entries)
    return result


@mcp.tool
def idm_find_references_to_dn(dn: str, limit: int | None = None) -> dict[str, Any]:
    """Find objects that reference a specific DN."""
    config = _config()
    result_limit = _clamp_limit(limit, 100, config["max_limit"])
    escaped = escape_ldap_filter_value(dn)
    search_filter = (
        f"(|(securityEquals={escaped})(groupMembership={escaped})(memberOf={escaped})"
        f"(uniqueMember={escaped})(member={escaped}))"
    )
    result = _search(
        config["search_base"],
        search_filter,
        REFERENCE_ATTRIBUTES,
        result_limit,
    )
    if result.get("ok"):
        result["objects"] = result.pop("entries")
    return result


@mcp.tool
def idm_search_objects(
    query: str,
    limit: int | None = None,
    include_security_attributes: bool = False,
) -> dict[str, Any]:
    """Search LDAP objects by cn, description, or ou."""
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    escaped = escape_ldap_filter_value(query)
    attrs = ["cn", "objectClass", "description", "owner"]
    if include_security_attributes:
        attrs += ["member", "uniqueMember", *SECURITY_ATTRIBUTES]
    result = _search(
        config["search_base"],
        f"(|(cn=*{escaped}*)(description=*{escaped}*)(ou=*{escaped}*))",
        attrs,
        result_limit,
    )
    if result.get("ok"):
        result["objects"] = result.pop("entries")
    return result


@mcp.tool
def idm_search_isd_users(
    query: str | None = None,
    site_code: str | None = None,
    previous_site_code: str | None = None,
    employee_type: str | None = None,
    employee_status: str | None = None,
    job_category: str | None = None,
    position_code: str | None = None,
    assignment_class: str | None = None,
    department: str | None = None,
    login_disabled: bool | None = None,
    limit: int | None = None,
    include_entitlements: bool = False,
    include_memberships: bool = False,
) -> dict[str, Any]:
    """Search ISD example users by custom ISD identity, employment, site, and role-adjacent fields."""
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    search_filter = _isd_user_filter(
        query=query,
        site_code=site_code,
        previous_site_code=previous_site_code,
        employee_type=employee_type,
        employee_status=employee_status,
        job_category=job_category,
        position_code=position_code,
        assignment_class=assignment_class,
        department=department,
        login_disabled=login_disabled,
    )
    attrs = ISD_USER_ATTRIBUTES[:]
    if include_memberships:
        attrs += ISD_MEMBERSHIP_ATTRIBUTES
    if include_entitlements:
        attrs += ISD_ENTITLEMENT_ATTRIBUTES
    result = _search(config["search_base"], search_filter, attrs, result_limit)
    if result.get("ok"):
        result["users"] = [
            _summarize_isd_user(
                user,
                include_entitlements=include_entitlements,
                include_memberships=include_memberships,
            )
            for user in result.pop("entries")
        ]
    return result


@mcp.tool
def idm_search_isd_users_by_attribute(
    attribute: str,
    value: str,
    exact: bool = True,
    limit: int | None = None,
) -> dict[str, Any]:
    """Search users by a whitelisted ISD/custom user attribute."""
    config = _config()
    attr = attribute.strip()
    if attr not in ISD_QUERYABLE_USER_ATTRIBUTES:
        return {
            "ok": False,
            "error": f"Attribute is not queryable. Allowed attributes: {sorted(ISD_QUERYABLE_USER_ATTRIBUTES)}",
        }
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    escaped = escape_ldap_filter_value(value)
    attr_filter = f"({attr}={escaped})" if exact else f"({attr}=*{escaped}*)"
    result = _search(
        config["search_base"],
        f"(&(objectClass=inetOrgPerson){attr_filter})",
        ISD_USER_ATTRIBUTES,
        result_limit,
    )
    if result.get("ok"):
        result["users"] = [_summarize_isd_user(user) for user in result.pop("entries")]
    return result


@mcp.tool
def idm_get_isd_user_profile(value: str, include_entitlements: bool = True) -> dict[str, Any]:
    """Get an ISD example user profile by uid, mail, cn, sn, isdPreferredSurname, employeeNumber, or isdWorkforceId."""
    config = _config()
    attrs = ISD_USER_ATTRIBUTES + (ISD_ENTITLEMENT_ATTRIBUTES if include_entitlements else [])
    result = _search(config["search_base"], _identity_filter(value), attrs, 2)
    if result.get("ok"):
        entries = result.pop("entries")
        result["user"] = _summarize_isd_user(entries[0], include_entitlements) if entries else None
        result["count"] = len(entries)
    return result


@mcp.tool
def idm_get_user_entitlements(value: str, include_raw: bool = False) -> dict[str, Any]:
    """Parse a user's IDM role, dynamic group, association, and entitlement attributes."""
    config = _config()
    result = _search(config["search_base"], _identity_filter(value), ISD_ENTITLEMENT_ATTRIBUTES, 2)
    if result.get("ok"):
        entries = result.pop("entries")
        user = entries[0] if entries else None
        result["user"] = {key: user.get(key) for key in ("dn", "cn", "uid", "mail", "isdWorkforceId")} if user else None
        result["entitlements"] = _build_entitlement_summary(user, include_raw=include_raw) if user else None
        result["count"] = len(entries)
    return result


@mcp.tool
def idm_find_users_with_isd_entitlement(
    query: str,
    limit: int | None = None,
    include_raw: bool = False,
    scan_limit: int | None = None,
) -> dict[str, Any]:
    """Find users with matching ISD example entitlement, role, dynamic group, association, Google group, LDAP group, or AD DN text.

    eDirectory does not support substring matching on several DirXML/nrf entitlement
    syntaxes, so this tool reads only entitlement-related attributes and filters
    them client-side.
    """
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    read_limit = _clamp_limit(scan_limit, config["export_default_limit"], config["export_max_limit"])
    q = str(query).strip()
    if not q:
        return {"ok": False, "error": "query is required"}

    result = _search(
        config["search_base"],
        "(objectClass=inetOrgPerson)",
        ISD_ENTITLEMENT_ATTRIBUTES,
        read_limit,
    )
    if not result.get("ok"):
        return result

    matches = []
    scanned = result.get("count", 0)
    for user in result.pop("entries"):
        searchable = {key: user.get(key) for key in ISD_ENTITLEMENT_ATTRIBUTES if key in user}
        if not _value_contains(searchable, q):
            continue
        item = {key: user.get(key) for key in ("dn", "cn", "uid", "mail", "isdWorkforceId")}
        item["entitlements"] = _build_entitlement_summary(user, include_raw=include_raw)
        matches.append(item)
        if len(matches) >= result_limit:
            break

    return {
        "ok": True,
        "count": len(matches),
        "limit": result_limit,
        "scanned": scanned,
        "scan_limit": read_limit,
        "search_base": config["search_base"],
        "filter": "client-side entitlement attribute scan over (objectClass=inetOrgPerson)",
        "query": q,
        "users": matches,
    }


@mcp.tool
def idm_search_isd_roles(
    query: str,
    limit: int | None = None,
    include_membership_attributes: bool = False,
    scan_limit: int | None = None,
) -> dict[str, Any]:
    """Find ISD example roles/dynamic groups by scanning assigned user role attributes.

    Some nrf role objects are readable by exact DN but are not returned by subtree
    searches for this bind account, so discovery is based on nrfMemberOf,
    securityEquals, nrfDynamicGroupMembership, and nrfGroupRoles values on users.
    """
    config = _config()
    result_limit = _clamp_limit(limit, config["default_limit"], config["max_limit"])
    read_limit = _clamp_limit(scan_limit, config["export_default_limit"], config["export_max_limit"])
    q = str(query).strip()
    if not q:
        return {"ok": False, "error": "query is required"}

    result = _search(
        config["search_base"],
        "(objectClass=inetOrgPerson)",
        ["cn", "mail", "isdWorkforceId", "nrfMemberOf", "securityEquals", "nrfDynamicGroupMembership", "nrfGroupRoles"],
        read_limit,
    )
    if not result.get("ok"):
        return result

    discovered: dict[str, dict[str, Any]] = {}
    for user in result.pop("entries"):
        sample_user = {key: user.get(key) for key in ("dn", "cn", "mail", "isdWorkforceId")}
        values: list[tuple[str, str]] = []
        for attr in ("nrfMemberOf", "securityEquals", "nrfDynamicGroupMembership"):
            values.extend((attr, str(v)) for v in _as_list(user.get(attr)))
        for raw_role in _as_list(user.get("nrfGroupRoles")):
            parsed = _parse_role_assignment(str(raw_role))
            if parsed.get("role_dn"):
                values.append(("nrfGroupRoles.role_dn", parsed["role_dn"]))
            if parsed.get("cause_group"):
                values.append(("nrfGroupRoles.cause_group", parsed["cause_group"]))

        for source_attr, dn in values:
            if not _value_contains(dn, q):
                continue
            role = discovered.setdefault(
                dn,
                {
                    "dn": dn,
                    "cn": _cn_from_dn(dn),
                    "matched_attributes": [],
                    "sample_users": [],
                },
            )
            if source_attr not in role["matched_attributes"]:
                role["matched_attributes"].append(source_attr)
            if len(role["sample_users"]) < 5:
                role["sample_users"].append(sample_user)
            if len(discovered) >= result_limit:
                break
        if len(discovered) >= result_limit:
            break

    roles = list(discovered.values())
    if include_membership_attributes:
        for role in roles:
            base = _search(role["dn"], "(objectClass=*)", ISD_ROLE_ATTRIBUTES, 1, search_scope=BASE)
            if base.get("ok") and base.get("entries"):
                role["object"] = base["entries"][0]
            elif not base.get("ok"):
                role["object_error"] = base.get("error")

    return {
        "ok": True,
        "count": len(roles),
        "limit": result_limit,
        "scanned": result.get("count", 0),
        "scan_limit": read_limit,
        "query": q,
        "roles": roles,
    }


@mcp.tool
def idm_parse_isd_entitlement_value(value: str) -> dict[str, Any]:
    """Parse one raw DirXML entitlement/ref/result or nrfGroupRoles value into readable fields."""
    stripped = value.strip()
    if stripped.startswith("<result"):
        parsed = _parse_entitlement_result(stripped)
        kind = "DirXML-EntitlementResult"
    elif "<assignment" in stripped:
        parsed = _parse_role_assignment(stripped)
        kind = "nrfGroupRoles"
    elif "<ref" in stripped:
        parsed = _parse_entitlement_ref(stripped)
        kind = "DirXML-EntitlementRef"
    elif "#" in stripped:
        parsed = _parse_association(stripped)
        kind = "DirXML-Associations"
    else:
        parsed = {"raw": stripped}
        kind = "unknown"
    return {"ok": True, "kind": kind, "parsed": parsed}


if __name__ == "__main__":
    transport = os.getenv("MCP_TRANSPORT", "sse")
    host = os.getenv("MCP_HOST", "0.0.0.0")
    port = _env_int("MCP_PORT", 8000)
    mcp.run(transport=transport, host=host, port=port)
