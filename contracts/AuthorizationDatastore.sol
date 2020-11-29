// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

// TODO: now that projects are split what do we do about imports?
import "../dependencies/libraires/security/structs/RoleData.sol";

// TODO: how does approval work? You approve and then they are automatically added to the members or there is another step that someone else must perform?
//       ... since the approval can be revoked. If the former then who double checks it and how are they informed of this?

// TODO: Require statement spam - disgusting but rather not use modifier since they are meant for external things calling in rather than internal checks

// TODO: Replace msg.sender with a context wrapper

 /**
  * Conract to store the role authorization data for the rest of the platform.
  * Should be expecting calls from the AuthorizationPlatform and return bools or bytes32 for evaluation results.
  */
contract AuthorizationDatastore {

    using RoleData for RoleData.Role;
    using RoleData for RoleData.ContractRoles;

    address private _authorizationPlatform;
    bytes32 private constant ROLE_GUARDIAN = bytes32(0x0);

    modifier onlyPlatform() {
        // TODO: Context is now in a different project
        require( msg.sender == _authorizationPlatform );
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

    constructor( address authorizationPlatform ) public {
        _authorizationPlatform = authorizationPlatform;
    }

    function registerContract( address contract_, bytes32 rootRole, address rootAccount ) external onlyPlatform() {        
        uint256 size;
        assembly { size:= extcodesize( contract_ ) }
        require( size > 0,                              "Contract argument is not a valid contract address" );
        require( !_contractExists( contract_ ),         "Contract already in data store" );
        require( _roleIsValid( contract_, rootRole ),  "Role cannot be the origin value of OxO" );

        _contractRoles[contract_].root = rootRole;
        _contractRoles[contract_].roles[rootRole].registerRole( rootRole, rootAccount );

        emit ContractRegistered( contract_, rootRole, rootAccount );
    }

    function createRole( address contract_, address submitter, bytes32 role, bytes32 adminRole, bytes32 approverRole ) external onlyPlatform() {
        require( _isRoot( contract_, submitter ) ,         "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),          "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, adminRole ),     "Admin role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, approverRole ),  "Approver role cannot be the origin value of OxO" );

        _contractRoles[contract_].roles[role].createRole( adminRole, approverRole );
        emit CreatedRole( contract_, submitter, role );
    }

    function setAdminRole( address contract_, address submitter, bytes32 role, bytes32 adminRole ) external onlyPlatform() {
        require( _isRoot( contract_, submitter ) ,     "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),          "Contract not in data store" );
        require( _roleIsValid( contract_, role ),      "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, adminRole ), "Admin role cannot be the origin value of OxO" );

        _contractRoles[contract_].roles[role].admin = adminRole;

        emit SetAdminRole( contract_, submitter, role, _contractRoles[contract_].roles[role].admin );
    }

    function setApproverRole( address contract_, address submitter, bytes32 role, bytes32 approverRole ) external onlyPlatform() {
        require( _isRoot( contract_, submitter ) ,         "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),          "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, approverRole ),  "Approver role cannot be the origin value of OxO" );

        _contractRoles[contract_].roles[role].approver = approverRole;

        emit SetApproverRole( contract_, submitter, role, _contractRoles[contract_].roles[role].approver );
    }

    function addRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external onlyPlatform() {
        require( _isRoot( contract_, submitter ) ,          "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),               "Contract not in data store" );
        require( _roleIsValid( contract_, role ),           "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, restrictedRole ), "Restricted role cannot be the origin value of OxO" );

        // TODO: What if you add a new role into this set and someone else has it? How do you check and undo their perms or just do not add it untill that is sorted?
        _contractRoles[contract_].roles[role].addRestrictedRole( restrictedRole );
        emit RestrictedRoleAdded( contract_, submitter, role, restrictedRole );
    }

    function removeRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external onlyPlatform() {
        require( _isRoot( contract_, submitter ) ,          "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),               "Contract not in data store" );
        require( _roleIsValid( contract_, role ),           "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, restrictedRole ), "Restricted role cannot be the origin value of OxO" );

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
    function assignRole( address contract_, bytes32 role, address account, address sender ) external onlyPlatform() {
        require( _contractExists( contract_ ),                              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),                          "Role cannot be the origin value of OxO" );
        require( _isAdmin( contract_, role, sender ),                     "Submitter has insufficient permissions" );
        require( !_hasRestrictedSharedRole( contract_, role, account ),   "RoleBasedAccessControl::assignRole account has restrictedRoles with role." ); // TODO: Error Message
        require( _isApprovedForRole( contract_, role, account ),          "Account is not approved for role." );
                
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
    function removeRole( address contract_, bytes32 role, address account, address sender ) external onlyPlatform() {
        require( _contractExists( contract_ ),           "Contract not in data store" );
        require( _roleIsValid( contract_, role ),       "Role cannot be the origin value of OxO" );
        require( _isAdmin( contract_, role, sender ),  "AccessControl: sender must be an admin to remove" );
        require( _hasRole( contract_, role, account ), "Account does not contain the role" );

        _contractRoles[contract_].roles[role].removeRole( account );
        emit RoleRemoved( contract_, role, account, sender );
    }

    function approveForRole( address contract_, bytes32 role, address account, address sender ) external onlyPlatform() {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),          "Role cannot be the origin value of OxO" );
        require( _isApprover( contract_, role, sender ),  "Sender does not contain the approver role" );

        _contractRoles[contract_].roles[role].approved[account] = true;
        emit RoleApproved( contract_, role, account, sender );
    }

    function revokeApproval( address contract_, bytes32 role, address account, address sender ) external onlyPlatform() {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),          "Role cannot be the origin value of OxO" );
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
    function renounceRole( address contract_, bytes32 role ) external {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role ),          "Role cannot be the origin value of OxO" );
        require( _hasRole( contract_, role, msg.sender ),  "Account does not contain the role" );

        _contractRoles[contract_].roles[role].removeRole( msg.sender );
        emit RoleRenounced( contract_, role, msg.sender);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole( address contract_, bytes32 role, address account ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _hasRole( contract_, role, account );
    }

    function hasRestrictedSharedRole( address contract_, bytes32 role, address account ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _hasRestrictedSharedRole( contract_, role, account );
    }

    function isApprovedForRole( address contract_, bytes32 role, address account ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _isApprovedForRole( contract_, role, account );
    }

    function isRoleRestricted( address contract_, bytes32 role, bytes32 restrictedRole ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _isRoleRestricted( contract_, role, restrictedRole );
    }

    /**
     * @dev Returns the admin role that controls `role`. See {assignRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setAdminRole}.
     */
    function getAdminRole( address contract_, bytes32 role ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role].admin;
    }

    function getApproverRole( address contract_, bytes32 role ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role].approver;
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount( address contract_, bytes32 role ) external view returns ( uint256 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
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
    function getRoleMember( address contract_, bytes32 role, uint256 index ) external view returns ( address ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role].getMember( index );
    }

    function hasAnyOfRoles( address contract_, address account, bytes32[] calldata roles ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _hasAnyOfRoles( contract_, account, roles );
    }

    function _hasRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role].isMember( account );
    }

    function _isApprovedForRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role].approved[account];
    }

    function _hasAnyOfRoles( address contract_, address account, bytes32[] calldata roles ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks
        for( uint256 iteration = 0; iteration <= roles.length; iteration++ ) {
            require( _roleIsValid( contract_, roles[iteration] ), "Role cannot be the origin value of OxO" );
            if( _hasRole( contract_, roles[iteration], account ) ) {
                return true;
            }
        }
        return false;
    }

    function _contractExists( address contract_ ) private view returns ( bool ) {
        return _contractRoles[contract_].root != ROLE_GUARDIAN;
    }

    function _roleIsValid( address contract_, bytes32 role ) private view returns ( bool ) {
        // Intent is to have the admin only be 0x0 prior to creation
        return _contractRoles[contract_].roles[role].admin != ROLE_GUARDIAN;
    }

    function _isRoot( address contract_, address account ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[_contractRoles[contract_].root].isMember( account );
    }

    function _isApprover( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role].approver, account );
    }

    function _isAdmin( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role].admin, account );
    }

    function _isRoleRestricted( address contract_, bytes32 role, bytes32 restrictedRole ) private view returns ( bool ) {

        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[role].getRestrictedRole( iteration ) == restrictedRole ) {
                return true;
            }
        }

        return false;
    }

    function _hasRestrictedSharedRole( address contract_, bytes32 role, address account ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks

        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[_contractRoles[contract_].roles[role].getRestrictedRole( iteration )].isMember( account ) ) {
                return true;
            }
        }

        return false;
    }
}
