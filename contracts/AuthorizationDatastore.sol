// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

// TODO: now that projects are split what do we do about imports?
import "../dependencies/libraires/security/structs/RoleData.sol";

// TODO: how does approval work? You approve and then they are automatically added to the members or there is another step that someone else must perform?
//       ... since the approval can be revoked. If the former then who double checks it and how are they informed of this?
// TODO: Replace msg.sender with a context wrapper

 /**
  * Conract to store the role authorization data for the rest of the platform.
  * Should be expecting calls from the authorizationProtocol and return bools or bytes32 for evaluation results.
  */
contract AuthorizationDatastore {

    using RoleData for RoleData.Role;
    using RoleData for RoleData.ContractRoles;

    address private _authorizationProtocol;
    bytes32 private constant ROLE_GUARDIAN = bytes32(0x0);

    modifier onlyPlatform() {
        require( msg.sender == _authorizationProtocol );
        _;
    }

    modifier contractExists( address contract_ ) {
        require( _contractRoles[contract_].root != ROLE_GUARDIAN, "Contract not in data store" );
        _;
    }

    modifier isRoot( address contract_, address account ) {
        require( _contractRoles[contract_].roles[_contractRoles[contract_].root].isMember( account ), "Submitter has insufficient permissions"  );
        _;
    }

    modifier roleExists( address contract_, bytes32 role ) {
        require( _contractRoles[contract_].roles[role].admin != ROLE_GUARDIAN, "Role does not exist" );
        _;
    }

    modifier validRole( address contract_, bytes32 role ) {
        require( role != ROLE_GUARDIAN, "Role cannot be the origin value of OxO" );
        _;
    }

    mapping( address => RoleData.ContractRoles ) private _contractRoles;

    event ContractRegistered( address indexed _contract, bytes32 indexed rootRole, address indexed rootAccount );
    event CreatedRole( address indexed contract_, address indexed creator, bytes32 role );
    event SetAdminRole( address indexed contract_, address submitter, bytes32 indexed role, bytes32 indexed adminRole );
    event SetApproverRole( address indexed contract_, address submitter, bytes32 indexed role, bytes32 indexed approverRole );
    event RestrictedRoleAdded( address indexed contract_, address submitter, bytes32 indexed role, bytes32 indexed restrictedRole );
    event RestrictedRoleRemoved( address indexed contract_, address submitter, bytes32 indexed role, bytes32 indexed restrictedRole );
    event RoleAssigned( address indexed contract_, bytes32 indexed role, address account, address indexed sender );
    event RoleRenounced( address indexed contract_, bytes32 indexed role, address indexed account );
    event RoleRemoved( address indexed contract_, bytes32 indexed role, address indexed account, address sender );
    event RoleApproved( address indexed contract_, bytes32 indexed role, address account, address indexed sender );
    event RoleApprovalRevoked( address indexed contract_, bytes32 indexed role, address account, address indexed sender );

    constructor( address authorizationProtocol ) public {
        _authorizationProtocol = authorizationProtocol;
    }

    function registerContract( address contract_, bytes32 rootRole, address rootAccount ) external onlyPlatform() {        
        uint256 size;
        assembly { size:= extcodesize( contract_ ) }
        require( size > 0,                                          "Contract argument is not a valid contract address" );
        require( _contractRoles[contract_].root == ROLE_GUARDIAN,   "Contract already in data store" );
        require( rootRole != ROLE_GUARDIAN,                         "Role cannot be the origin value of OxO" );

        _contractRoles[contract_].root = rootRole;
        _contractRoles[contract_].roles[rootRole].registerRole( rootRole, rootAccount );

        emit ContractRegistered( contract_, rootRole, rootAccount );
    }

    function createRole( address contract_, address submitter, bytes32 role, bytes32 adminRole, bytes32 approverRole ) external 
        onlyPlatform() 
        contractExists( contract_ )
        isRoot( contract_, submitter )
    {
        require( _contractRoles[contract_].roles[role].admin == ROLE_GUARDIAN, "Role signature already exists" );
        
        // Compiler stack overflow if using TWO modifiers to check roles therefore instead of 1 modifier perform the checks here
        require( adminRole != ROLE_GUARDIAN, "Role cannot be the origin value of OxO" );
        require( approverRole != ROLE_GUARDIAN, "Role cannot be the origin value of OxO" );
        
        _contractRoles[contract_].roles[role].createRole( adminRole, approverRole );
        emit CreatedRole( contract_, submitter, role );
    }

    function setAdminRole( address contract_, address submitter, bytes32 role, bytes32 adminRole ) external 
        onlyPlatform() 
        contractExists( contract_ )
        isRoot( contract_, submitter )
        roleExists( contract_, role )
        validRole( contract_, adminRole )
    {
        _contractRoles[contract_].roles[role].admin = adminRole;
        emit SetAdminRole( contract_, submitter, role, _contractRoles[contract_].roles[role].admin );
    }

    function setApproverRole( address contract_, address submitter, bytes32 role, bytes32 approverRole ) external 
        onlyPlatform() 
        contractExists( contract_ )
        isRoot( contract_, submitter )
        roleExists( contract_, role )
        validRole( contract_, approverRole )
    {
        _contractRoles[contract_].roles[role].approver = approverRole;
        emit SetApproverRole( contract_, submitter, role, _contractRoles[contract_].roles[role].approver );
    }

    function addRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external 
        onlyPlatform() 
        contractExists( contract_ )
        isRoot( contract_, submitter )
        roleExists( contract_, role )
        validRole( contract_, restrictedRole )
    {
        // TODO: What if you add a new role into this set and someone else has it? How do you check and undo their perms or 
        // just do not add it untill that is sorted?
        _contractRoles[contract_].roles[role].addRestrictedRole( restrictedRole );
        emit RestrictedRoleAdded( contract_, submitter, role, restrictedRole );
    }

    function removeRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external 
        onlyPlatform()
        contractExists( contract_ )
        isRoot( contract_, submitter )
        roleExists( contract_, role )
        validRole( contract_, restrictedRole )
    {
        _contractRoles[contract_].roles[role].removeRestrictedRole( restrictedRole );
        emit RestrictedRoleRemoved( contract_, submitter, role, restrictedRole );
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleAssigned}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function assignRole( address contract_, bytes32 role, address account, address sender ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
    {
        require( _isAdmin( contract_, role, sender ),               "Submitter has insufficient permissions" );
        require( !_hasRestrictedRole( contract_, role, account ),   "Account contains a restricted role" );
        require( _isApprovedForRole( contract_, role, account ),    "Account is not approved for role." );
                
        _contractRoles[contract_].roles[role].assignRole( account );
        emit RoleAssigned( contract_, role, account, sender );
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function removeRole( address contract_, bytes32 role, address account, address sender ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
    {
        require( _isAdmin( contract_, role, sender ),  "Admin only" ); // TODO: What about root?
        require( _hasRole( contract_, role, account ), "Account does not contain the role" );

        _contractRoles[contract_].roles[role].removeRole( account );
        emit RoleRemoved( contract_, role, account, sender );
    }

    function approveForRole( address contract_, bytes32 role, address account, address sender ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
    {
        require( _isApprover( contract_, role, sender ),  "Sender does not contain the approver role" );

        _contractRoles[contract_].roles[role].approved[account] = true;
        emit RoleApproved( contract_, role, account, sender );
    }

    function revokeApproval( address contract_, bytes32 role, address account, address sender ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
    {
        require( _isApprover( contract_, role, sender ),  "Sender does not contain the approver role" );

        _contractRoles[contract_].roles[role].approved[account] = false;
        emit RoleApprovalRevoked( contract_, role, account, sender );
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {assignRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     */
    function renounceRole( address contract_, bytes32 role ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
    {
        require( _hasRole( contract_, role, msg.sender ),  "Account does not contain the role" );

        _contractRoles[contract_].roles[role].removeRole( msg.sender );
        emit RoleRenounced( contract_, role, msg.sender);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole( address contract_, bytes32 role, address account ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bool ) 
    {
        return _hasRole( contract_, role, account );
    }

    function hasRestrictedRole( address contract_, bytes32 role, address account ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bool )
    {
        return _hasRestrictedRole( contract_, role, account );
    }

    function isApprovedForRole( address contract_, bytes32 role, address account ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bool )
    {
        return _isApprovedForRole( contract_, role, account );
    }

    function isRoleRestricted( address contract_, bytes32 role, bytes32 restrictedRole ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bool )
    {
        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[role].getRestrictedRole( iteration ) == restrictedRole ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @dev Returns the admin role that controls `role`. See {assignRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setAdminRole}.
     */
    function getAdminRole( address contract_, bytes32 role ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bytes32 ) 
    {
        return _contractRoles[contract_].roles[role].admin;
    }

    function getApproverRole( address contract_, bytes32 role ) external 
        onlyPlatform() 
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( bytes32 ) 
    {
        return _contractRoles[contract_].roles[role].approver;
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount( address contract_, bytes32 role ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( uint256 ) 
    {
        return _contractRoles[contract_].roles[role].memberCount();
    }

    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember( address contract_, bytes32 role, uint256 index ) external 
        onlyPlatform()
        contractExists( contract_ )
        roleExists( contract_, role )
        view returns ( address )
    {
        return _contractRoles[contract_].roles[role].getMember( index );
    }
    
    function isRoleCreated( address contract_, bytes32 role ) external
        onlyPlatform()
        contractExists( contract_ )
        view returns ( bool )
    {
        return _contractRoles[contract_].roles[role].admin != ROLE_GUARDIAN;
    }
    
    function isContractRegistered( address contract_ ) external
        onlyPlatform()
        view returns ( bool )
    {
        return _contractRoles[contract_].root != ROLE_GUARDIAN;
    }

    function _hasRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role].isMember( account );
    }

    function _isApprovedForRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role].approved[account];
    }

    function _isApprover( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role].approver, account );
    }

    function _isAdmin( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role].admin, account );
    }

    function _hasRestrictedRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks

        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[_contractRoles[contract_].roles[role].getRestrictedRole( iteration )].isMember( account ) ) {
                return true;
            }
        }

        return false;
    }
}