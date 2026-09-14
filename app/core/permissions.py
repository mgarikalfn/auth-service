"""System permission definitions."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionDefinition:
    key: str
    description: str


SYSTEM_PERMISSIONS = (
    PermissionDefinition(
        key="organization.read",
        description="View organization information",
    ),
    PermissionDefinition(
        key="organization.update",
        description="Update organization information",
    ),
    PermissionDefinition(
        key="members.read",
        description="View organization members",
    ),
    PermissionDefinition(
        key="members.create",
        description="Invite members to the organization",
    ),
    PermissionDefinition(
        key="members.update",
        description="Update organization members",
    ),
    PermissionDefinition(
        key="members.delete",
        description="Remove members from the organization",
    ),
    PermissionDefinition(
        key="roles.read",
        description="View organization roles",
    ),
    PermissionDefinition(
        key="roles.create",
        description="Create organization roles",
    ),
    PermissionDefinition(
        key="roles.update",
        description="Update organization roles",
    ),
    PermissionDefinition(
        key="roles.delete",
        description="Delete organization roles",
    ),
)