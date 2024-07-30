@advice("Access is automatically approved because you are on-call AND in the platform team")
permit (
    principal in PagerDuty::OnCall::All::"int_pd_123", // ANYONE on-call
    action == Access::Action::"Activate", // auto-approved access
    resource is AWS::IDC::AccountGrant
)
when
{
    principal in AWS::IDC::Group::"12345-12345" // Platform engineers group
}
when
{
    resource.target in AWS::OrgUnit::"ou-6nde-zza4kxwm"
} // Security OU in AWS
when
{
    resource.role == AWS::IDC::PermissionSet::"arn:aws:sso:::permissionSet/ssoins-825968feece9a0b6/ps-dda57372ebbfeb94"
}; // AWSAdministratorAccess role
