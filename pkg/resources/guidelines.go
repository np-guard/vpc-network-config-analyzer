package resources

/*
Security groups guidelines

Rules

    Each security group defines different sets of network rules that define the incoming and outgoing traffic for a virtual server instance.
	You can specify rules for both IPv4 and IPv6.

	When a new security group is created by using the IBM Cloud console, the default behavior is to create a single rule that allows all outbound traffic
	from the virtual server instance. You must clear the "Create group with a default rule to allow all outbound traffic" check box to create the security group with no rules.
	A security group with no rules blocks all traffic (both inbound and outbound).

	To allow inbound traffic, outbound traffic, or both, you must add at least one security group that includes security group rules that allow traffic.

	Security group rules only can be permissive. Traffic is blocked by default.

	Users with the Manage Security Groups privilege can add, edit, or delete rules in a security group.
	Changes to security group rules are automatically applied and can be modified at any time.

	The order of rules within a security group does not matter. The priority always falls to the least restrictive rule.

    Rules are stateful. Connections established prior to a security group change are not altered.
	New connections abide by rules that exist at the time connectivity is established.

	Security groups do not override operating system firewalls on the virtual server. Even if a more restrictive firewall exists on the operating system
	than what is applied by the security group, the operating system rules will still be enforced.

	If your virtual server needs access to internal services, such as an update server, network attached storage (NAS), or advanced monitoring,
	ensure that the security group rules accommodate traffic for those internal services. For more information, see IBM Cloud IP ranges.

Interfaces

    A security group can be applied to a private network, a public network, or both network interface types.
    You can attach one or more security groups to the list of security groups that are assigned to a network interface. The security group rules of each security group apply to the associated virtual server instances.
    The first time that you assign an existing security group to a network interface (public or private), a restart is required for each interface. However, if the public and private interfaces were assigned to the security group at the same time, then only one restart is required. After a restart, changes are automatically applied.

Access

    All users within an account can read, attach, and detach security groups on the virtual server instances to which they have access. Only users with the Manage Security Groups privilege in Network Permissions can create, update and delete security groups.
    You cannot assign security groups to bare metal servers.

Deletion

    You cannot delete a security group that is assigned to one or more running virtual server instances.
    You cannot delete a security group that another security group is referencing in one of its rules.

*/
