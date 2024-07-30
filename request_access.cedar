// Allow all users to request access to all resources
permit (
    principal,
    action == Access::Action::"Request",
    resource
);