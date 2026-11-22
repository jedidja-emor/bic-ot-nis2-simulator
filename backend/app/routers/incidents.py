"""NIS2 Article 21 / Article 23 incident management."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..audit import write_audit
from ..crud import incident_to_dict
from ..database import get_db
from ..deps import (
    enforce_any_permission,
    enforce_permission,
    enforce_tenant_membership,
    get_current_user,
    get_user_tenant_ids,
    is_platform_admin,
)
from ..models import Incident, IncidentSeverity, IncidentStatus, User
from ..nis2 import (
    compute_timer,
    deadlines_for,
    is_early_warning_late,
    is_notification_late,
)
from ..schemas import IncidentCreate, IncidentUpdate
from ..timeutils import now_iso, utcnow

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def _authorize(db: Session, user: User, incident: Incident, permission: str) -> None:
    enforce_tenant_membership(db, user, incident.tenant_id)
    enforce_permission(db, user, permission, incident.tenant_id)


def _incident_payload(incident: Incident) -> dict:
    data = incident_to_dict(incident)
    data.update(compute_timer(incident))
    return data


def _resolve_declare_tenant(db: Session, user: User, requested: int | None) -> int:
    if requested is not None:
        enforce_tenant_membership(db, user, requested)
        enforce_permission(db, user, "incident:declare", requested)
        return requested

    if is_platform_admin(db, user):
        raise HTTPException(status_code=400, detail="tenant_id is required for platform admins")

    tenant_ids = get_user_tenant_ids(db, user)
    if len(tenant_ids) == 1:
        enforce_permission(db, user, "incident:declare", tenant_ids[0])
        return tenant_ids[0]
    raise HTTPException(status_code=400, detail="tenant_id is required")


@router.get("")
def list_incidents(
    tenant_id: int | None = Query(default=None),
    status: IncidentStatus | None = Query(default=None),
    severity: IncidentSeverity | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "incident:read", tenant_id)
        if tenant_id is not None:
            query = query.filter(Incident.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "incident:read", tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "incident:read")
        if not allowed:
            return []
        query = query.filter(Incident.tenant_id.in_(allowed))

    if status is not None:
        query = query.filter(Incident.status == status.value)
    if severity is not None:
        query = query.filter(Incident.severity == severity.value)
    return [_incident_payload(row) for row in query.order_by(Incident.id.desc()).all()]


@router.post("", status_code=201)
def declare_incident(
    payload: IncidentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tenant_id = _resolve_declare_tenant(db, current_user, payload.tenant_id)
    declared = utcnow()
    early_deadline, notification_deadline = deadlines_for(declared)
    now = now_iso()

    incident = Incident(
        tenant_id=tenant_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity.value,
        status=IncidentStatus.open.value,
        article=payload.article.value,
        declared_at=now,
        early_warning_deadline=early_deadline,
        notification_deadline=notification_deadline,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    write_audit(
        db,
        tenant_id=tenant_id,
        actor_user_id=current_user.id,
        action="incident:declare",
        target_type="incident",
        target_id=incident.id,
        details={
            "severity": incident.severity,
            "article": incident.article,
            "declared_at": incident.declared_at,
            "early_warning_deadline": incident.early_warning_deadline,
            "notification_deadline": incident.notification_deadline,
        },
    )
    db.commit()
    return _incident_payload(incident)


@router.get("/timers")
def list_timers(
    tenant_id: int | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if is_platform_admin(db, current_user):
        enforce_permission(db, current_user, "incident:read", tenant_id)
        if tenant_id is not None:
            query = query.filter(Incident.tenant_id == tenant_id)
    else:
        allowed = get_user_tenant_ids(db, current_user)
        if tenant_id is not None:
            enforce_tenant_membership(db, current_user, tenant_id)
            enforce_permission(db, current_user, "incident:read", tenant_id)
            allowed = [tenant_id]
        else:
            enforce_any_permission(db, current_user, "incident:read")
        if not allowed:
            return []
        query = query.filter(Incident.tenant_id.in_(allowed))

    now = utcnow()
    result = []
    for incident in query.order_by(Incident.id.desc()).all():
        data = incident_to_dict(incident)
        data.update(compute_timer(incident, now=now))
        result.append(data)
    return result


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    _authorize(db, current_user, incident, "incident:read")
    return _incident_payload(incident)


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    _authorize(db, current_user, incident, "incident:declare")

    changes: dict = {}
    if payload.severity is not None:
        incident.severity = payload.severity.value
        changes["severity"] = incident.severity
    if payload.description is not None:
        incident.description = payload.description
        changes["description"] = "updated"

    if payload.status is not None:
        target = payload.status
        if target == IncidentStatus.resolved:
            if incident.status == IncidentStatus.closed.value:
                raise HTTPException(status_code=409, detail="Closed incidents cannot be resolved")
            if incident.status == IncidentStatus.resolved.value:
                raise HTTPException(status_code=409, detail="Incident is already resolved")
            incident.status = IncidentStatus.resolved.value
            incident.resolved_at = now_iso()
            changes["status"] = incident.status
            changes["resolved_at"] = incident.resolved_at
        elif target == IncidentStatus.closed:
            if incident.status != IncidentStatus.resolved.value:
                raise HTTPException(status_code=409, detail="Only resolved incidents can be closed")
            incident.status = IncidentStatus.closed.value
            incident.closed_at = now_iso()
            changes["status"] = incident.status
            changes["closed_at"] = incident.closed_at
        else:
            raise HTTPException(
                status_code=400,
                detail="PATCH may only transition an incident to 'resolved' or 'closed'",
            )

    if changes:
        incident.updated_at = now_iso()
        write_audit(
            db,
            tenant_id=incident.tenant_id,
            actor_user_id=current_user.id,
            action="incident:update",
            target_type="incident",
            target_id=incident.id,
            details=changes,
        )
    db.commit()
    return _incident_payload(incident)


@router.post("/{incident_id}/early-warning")
def send_early_warning(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    _authorize(db, current_user, incident, "incident:early_warning")

    if incident.status != IncidentStatus.open.value:
        raise HTTPException(
            status_code=409,
            detail=f"Early warning requires status 'open' (current={incident.status})",
        )

    late = is_early_warning_late(incident)
    now = now_iso()
    incident.early_warning_sent_at = now
    incident.status = IncidentStatus.early_warning_sent.value
    incident.updated_at = now
    write_audit(
        db,
        tenant_id=incident.tenant_id,
        actor_user_id=current_user.id,
        action="incident:early_warning",
        target_type="incident",
        target_id=incident.id,
        details={
            "sent_at": now,
            "deadline": incident.early_warning_deadline,
            "is_overdue": late,
        },
    )
    db.commit()
    data = _incident_payload(incident)
    data["is_overdue"] = late
    return data


@router.post("/{incident_id}/notify")
def notify_authority(
    incident_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    incident = _get_incident(db, incident_id)
    _authorize(db, current_user, incident, "incident:notify")

    if incident.status != IncidentStatus.early_warning_sent.value:
        raise HTTPException(
            status_code=409,
            detail=(
                "Authority notification requires status 'early_warning_sent' "
                f"(current={incident.status})"
            ),
        )

    late = is_notification_late(incident)
    now = now_iso()
    incident.notification_sent_at = now
    incident.status = IncidentStatus.notified_authority.value
    incident.updated_at = now
    write_audit(
        db,
        tenant_id=incident.tenant_id,
        actor_user_id=current_user.id,
        action="incident:notify",
        target_type="incident",
        target_id=incident.id,
        details={
            "sent_at": now,
            "deadline": incident.notification_deadline,
            "is_overdue": late,
        },
    )
    db.commit()
    data = _incident_payload(incident)
    data["is_overdue"] = late
    return data
