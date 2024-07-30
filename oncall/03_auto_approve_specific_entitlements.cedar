@advice("Access is automatically approved because you are on-call")
permit (
    principal in
        PagerDuty::OnCall::"PNE4HSJ", // On-call members for Demo Schedule
    action == Access::Action::"Activate", // auto-approved access
    resource is AWS::IDC::AccountGrant
)
when
{
    resource.target.tags.contains({key:"department", value:"engineering"})
} // Security OU in AWS
when
{
    resource.role == AWS::IDC::PermissionSet::"arn:aws:sso:::permissionSet/ssoins-825968feece9a0b6/ps-dda57372ebbfeb94"
}; // AWSAdministratorAccess role
