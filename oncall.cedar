@advice("Access is automatically approved because you are on-call")
permit (
    principal in
        PagerDuty::OnCall::"PNE4HSJ", // On-call members for Demo Schedule
    action == Access::Action::"Activate", // auto-approved access
    resource is AWS::IDC::AccountGrant
)
when
{
    resource.target in AWS::OrgUnit::"ou-6nde-zza4kxwm"
} // Security OU in AWS
when
{
    resource.role == AWS::IDC::PermissionSet::"arn:aws:sso:::permissionSet/ssoins-825968feece9a0b6/ps-dda57372ebbfeb94"
}; // AWSAdministratorAccess role

@advice("Contractors may not request access to accounts containing customer data")
forbid (
    principal in Okta::Group::"12345-12345-12345", // External Contractors group
    action == Access::Action::"Request", // auto-approved access
    resource is AWS::IDC::AccountEntitlement
)
when { resource.target.tags.contains({key:"customer-data", value:"true"}) };

@advice("All users have Breakglass access for all Okta Groups")
permit (
    principal,
    action == Access::Action::"BreakglassActivate",
    resource is Okta::GroupGrant
);