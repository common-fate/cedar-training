@advice("Breakglass access to security accounts is restricted")
forbid (
    principal,
    action == Access::Action::"Request",
    resource is AWS::IDC::AccountEntitlement
)
when
{
    resource.target in AWS::OrgUnit::"ou-1234-5678abcdef" // Security Accounts
}
unless { principal in AWS::IDC::Group::"<ID_OF_SECURITY_GROUP>" };
