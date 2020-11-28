// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

// TODO: now that projects are split what do we do about imports?
import "../dependencies/libraires/security/structs/RoleData.sol";

// TODO: how does approval work? You approve and then they are automatically added to the members or there is another step that someone else must perform?
//       ... since the approval can be revoked. If the former then who double checks it and how are they informed of this?

// TODO: Require statement spam - disgusting but rather not use modifier since they are meant for external things calling in rather than internal checks

// TODO: Replace msg.sender with a context wrapper

// TODO: Granting and Approval of roles is semantically ambiguous, need clearer / more distinct names

// TODO: Can only have 3 indexes, what do we care to be able to search for?

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
    event CreatedRole( address indexed _contract, address indexed creator, bytes32 role );
    event SetAdminRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 previousAdminRole, bytes32 indexed newAdminRole );
    event SetApproverRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 approverRole, bytes32 indexed newApproverRole );
    event RestrictedRoleAdded( address indexed _contract, address submitter, bytes32 indexed role, bytes32 indexed restrictedSharedRole );
    event RestrictedRoleRemoved( address indexed _contract, address submitter, bytes32 indexed role, bytes32 indexed restrictedSharedRole );
    event RoleGranted( address indexed _contract, bytes32 indexed role, address account, address indexed sender );
    event RoleRemoved( address indexed _contract, bytes32 indexed role, address indexed account, address sender );
    event RoleRevoked( address indexed _contract, bytes32 indexed role, address indexed account, address sender );
    event RoleApproved( address indexed _contract, bytes32 indexed role, address approvee, address indexed approver );
    event RoleApprovalRevoked( address indexed _contract, bytes32 indexed role, address approvee, address indexed approver );
    event RoleRenounced( address indexed _contract, bytes32 indexed role, address indexed account );

    constructor( address authorizationPlatform_ ) public {
        _authorizationPlatform = authorizationPlatform_;
    }

    function registerContract( address contract_, bytes32 rootRole_, address newRootAddress_ ) external onlyPlatform() {        
        uint256 size;
        assembly { size:= extcodesize( contract_ ) }
        require( size > 0,                              "Contract argument is not a valid contract address" );
        require( !_contractExists( contract_ ),         "Contract already in data store" );
        require( _roleIsValid( contract_, rootRole_ ),  "Role cannot be the origin value of OxO" );

        _contractRoles[contract_].root = rootRole_;
        _contractRoles[contract_].roles[rootRole_].registerRole( rootRole_, newRootAddress_ );

        emit ContractRegistered( contract_, rootRole_, newRootAddress_ );
    }

    function createRole( address contract_, address submitter_, bytes32 role_, bytes32 adminRole_, bytes32 approverRole_ ) external onlyPlatform() {
        require( _isRoot( contract_, submitter_ ) ,         "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),          "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, adminRole_ ),     "Admin role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, approverRole_ ),  "Approver role cannot be the origin value of OxO" );

        _contractRoles[contract_].roles[role_].createRole( adminRole_, approverRole_ );
        emit CreatedRole( contract_, submitter_, role_ );
    }

    function setAdminRole( address contract_, address submitter_, bytes32 role_, bytes32 adminRole_ ) external onlyPlatform() {
        require( _isRoot( contract_, submitter_ ) ,     "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),          "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),      "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, adminRole_ ), "Admin role cannot be the origin value of OxO" );

        bytes32 previousAdminRole_ = _contractRoles[contract_].roles[role_].admin;
        _contractRoles[contract_].roles[role_].admin = adminRole_;

        emit SetAdminRole( contract_, submitter_, role_, previousAdminRole_, _contractRoles[contract_].roles[role_].admin );
    }

    function setApproverRole( address contract_, address submitter_, bytes32 role_, bytes32 approverRole_ ) external onlyPlatform() {
        require( _isRoot( contract_, submitter_ ) ,         "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),          "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, approverRole_ ),  "Approver role cannot be the origin value of OxO" );

        bytes32 previousApproverRole_ = _contractRoles[contract_].roles[role_].approver;
        _contractRoles[contract_].roles[role_].approver = approverRole_;

        emit SetApproverRole( contract_, submitter_, role_, previousApproverRole_, _contractRoles[contract_].roles[role_].approver );
    }

    function addRestrictedRole( address contract_, address submitter_, bytes32 role_, bytes32 restrictedRole_ ) external onlyPlatform() {
        require( _isRoot( contract_, submitter_ ) ,          "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),               "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),           "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, restrictedRole_ ), "Restricted role cannot be the origin value of OxO" );

        // TODO: What if you add a new role into this set and someone else has it? How do you check and undo their perms or just do not add it untill that is sorted?
        _contractRoles[contract_].roles[role_].addRestrictedRole( restrictedRole_ );
        emit RestrictedRoleAdded( contract_, submitter_, role_, restrictedRole_ );
    }

    function removeRestrictedRole( address contract_, address submitter_, bytes32 role_, bytes32 restrictedRole_ ) external onlyPlatform() {
        require( _isRoot( contract_, submitter_ ) ,          "Submitter has insufficient permissions" );
        require( _contractExists( contract_ ),               "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),           "Role cannot be the origin value of OxO" );
        require( _roleIsValid( contract_, restrictedRole_ ), "Restricted role cannot be the origin value of OxO" );

        _contractRoles[contract_].roles[role_].removeRestrictedRole( restrictedRole_ );
        emit RestrictedRoleRemoved( contract_, submitter_, role_, restrictedRole_ );
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ),                              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),                          "Role cannot be the origin value of OxO" );
        require( _isAdmin( contract_, role_, sender_ ),                     "Submitter has insufficient permissions" );
        require( !_hasRestrictedSharedRole( contract_, role_, account_ ),   "RoleBasedAccessControl::grantRole account has restrictedRoles with role." ); // TODO: Error Message
        require( _isApprovedForRole( contract_, role_, account_ ),          "Account is not approved for role." );
                
        _contractRoles[contract_].roles[role_].grantRole( account_ );
        emit RoleGranted( contract_, role_, account_, sender_ );
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
    function removeRole( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ),           "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),       "Role cannot be the origin value of OxO" );
        require( _isAdmin( contract_, role_, sender_ ),  "AccessControl: sender must be an admin to remove" );
        require( _hasRole( contract_, role_, account_ ), "Account does not contain the role" );

        _contractRoles[contract_].roles[role_].removeRole( account_ );
        emit RoleRemoved( contract_, role_, account_, sender_ );
    }

    function approveForRole( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),          "Role cannot be the origin value of OxO" );
        require( _isApprover( contract_, role_, sender_ ),  "Sender does not contain the approver role" );

        _contractRoles[contract_].roles[role_].approved[account_] = true;
        emit RoleApproved( contract_, role_, account_, sender_ );
    }

    function revokeApproval( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),          "Role cannot be the origin value of OxO" );
        require( _isApprover( contract_, role_, sender_ ),  "Sender does not contain the approver role" );

        _contractRoles[contract_].roles[role_].approved[account_] = false;
        emit RoleApprovalRevoked( contract_, role_, account_, sender_ );
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
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
    function renounceRole( address contract_, bytes32 role_ ) external {
        require( _contractExists( contract_ ),              "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),          "Role cannot be the origin value of OxO" );
        require( _hasRole( contract_, role_, msg.sender ),  "Account does not contain the role" );

        _contractRoles[contract_].roles[role_].removeRole( msg.sender );
        emit RoleRenounced( contract_, role_, msg.sender);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _hasRole( contract_, role_, account_ );
    }

    function hasRestrictedSharedRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _hasRestrictedSharedRole( contract_, role_, account_ );
    }

    function isApprovedForRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _isApprovedForRole( contract_, role_, account_ );
    }

    function isRoleRestricted( address contract_, bytes32 role_, bytes32 restrictedRole_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _isRoleRestricted( contract_, role_, restrictedRole_ );
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setAdminRole}.
     */
    function getAdminRole( address contract_, bytes32 role_ ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role_].admin;
    }

    function getApproverRole( address contract_, bytes32 role_ ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role_].approver;
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount( address contract_, bytes32 role_ ) external view returns ( uint256 ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role_].memberCount();
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
    function getRoleMember( address contract_, bytes32 role_, uint256 index_ ) external view returns ( address ) {
        require( _contractExists( contract_ ),      "Contract not in data store" );
        require( _roleIsValid( contract_, role_ ),  "Role cannot be the origin value of OxO" );
        return _contractRoles[contract_].roles[role_].getMember( index_ );
    }

    function hasAnyOfRoles( address contract_, address account_, bytes32[] calldata roles_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _hasAnyOfRoles( contract_, account_, roles_ );
    }

    function _hasRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role_].isMember( account_ );
    }

    function _isApprovedForRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role_].approved[account_];
    }

    function _hasAnyOfRoles( address contract_, address account_, bytes32[] calldata roles_ ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks
        for( uint256 iteration = 0; iteration <= roles_.length; iteration++ ) {
            require( _roleIsValid( contract_, roles_[iteration] ), "Role cannot be the origin value of OxO" );
            if( _hasRole( contract_, roles_[iteration], account_ ) ) {
                return true;
            }
        }
        return false;
    }

    function _contractExists( address contract_ ) private view returns ( bool ) {
        return _contractRoles[contract_].root != ROLE_GUARDIAN;
    }

    function _roleIsValid( address contract_, bytes32 role_ ) private view returns ( bool ) {
        // Intent is to have the admin only be 0x0 prior to creation
        return _contractRoles[contract_].roles[role_].admin != ROLE_GUARDIAN;
    }

    function _isRoot( address contract_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[_contractRoles[contract_].root].isMember( account_ );
    }

    function _isApprover( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role_].approver, account_ );
    }

    function _isAdmin( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role_].admin, account_ );
    }

    function _isRoleRestricted( address contract_, bytes32 role_, bytes32 restrictedRole_ ) private view returns ( bool ) {

        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role_].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[role_].getRestrictedRole( iteration ) == restrictedRole_ ) {
                return true;
            }
        }

        return false;
    }

    function _hasRestrictedSharedRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks

        for( uint256 iteration = 0; iteration < _contractRoles[contract_].roles[role_].restrictedCount(); iteration++ ) {
            if ( _contractRoles[contract_].roles[_contractRoles[contract_].roles[role_].getRestrictedRole( iteration )].isMember( account_ ) ) {
                return true;
            }
        }

        return false;
    }
}
