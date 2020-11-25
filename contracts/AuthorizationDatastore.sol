// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

import "hardhat/console.sol";

// TODO: now that projects are split what do we do about imports?
import "../dependencies/libraires/security/structs/RoleData.sol";

// TODO: how does approval work? You approve and then they are automatically added to the members or there is another step that someone else must perform?
//       ... since the approval can be revoked. If the former then who double checks it and how are they informed of this?

 /**
  * Conract to store the role authorization data for the rest of the platform.
  * Should be expecting calls from the AuthorizationPlatform and return bools or bytes32 for evaluation results.
  */
contract AuthorizationDatastore {

    using RoleData for RoleData.Role;
    using RoleData for RoleData.ContractRoles;

    address private _authorizationPlatform;

    event ContractRegistered( address indexed _contract, bytes32 indexed rootRole, address indexed rootAccount );
    event CreatedRole( address indexed _contract, address indexed creator, bytes32 role );
    event SetAdminRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 previousAdminRole, bytes32 indexed newAdminRole );
    event SetApproverRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 approverRole, bytes32 indexed newApproverRole );
    event AddedRestrictedSharedRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 indexed restrictedSharedRole );
    event RemovedRestrictedSharedRole( address indexed _contract, address submitter, bytes32 indexed role, bytes32 indexed restrictedSharedRole );
    
    // TODO: Can only have 3 indexes, what do we care to be able to search for?
    event RoleGranted( address indexed _contract, bytes32 indexed role, address account, address indexed sender );
    event RoleRemoved( address indexed _contract, bytes32 indexed role, address indexed account, address sender );
    
    event RoleRevoked( address indexed _contract, bytes32 indexed role, address indexed account, address sender );

    event RoleApproved( address indexed _contract, bytes32 indexed role, address approvee, address indexed approver );
    event RoleApprovalRevoked( address indexed _contract, bytes32 indexed role, address approvee, address indexed approver );

    event RoleRenounced( address indexed _contract, bytes32 indexed role, address indexed account );

    // TODO: Granting and Approval of roles is semantically ambiguous, need clearer / more distinct names

    modifier onlyPlatform() {
        // TODO: Context is now in a different project
        require( Context._msgSender() == authorizationPlatform );
        _;
    }

    mapping( address => RoleData.ContractRoles ) private _contractRoles;

    constructor( address authorizationPlatform_ ) public {
        console.log( "Instantiating AuthorizationDatastore." );

        _authorizationPlatform = authorizationPlatform_;

        console.log( "Instantiated AuthorizationDatastore." );
    }

    function registerContract( address contract_, bytes32 rootRole_, address newRootAddress_ ) external onlyPlatform() {        
        uint256 size;
        assembly { size:= extcodesize(contract_) };
        require( size > 0, "Contract argument is not a valid contract address" );
        require( !_contractExists(contract_), "Contract already in data store" );

        _contractRoles[contract_].root = rootRole_;
        _contractRoles[contract_].roles[rootRole_].admin = rootRole_;
        _contractRoles[contract_].roles[rootRole_].members.add(newRootAddress_);
        _contractRoles[contract_].roles[rootRole_].approved[newRootAddress_] = true;

        emit ContractRegistered( contract_, rootRole_, newRootAddress_ );
    }

    function createRole( address contract_, address submitter_, bytes32 role_, bytes32 adminRole_, bytes32 approverRole_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isRoot( contract_, submitter_ ) , "Submitter has insufficient permissions" );

        // TODO: check how to create this with syntax highligher
        Role newRole_ = Role({
            admin:                  adminRole_,
            approver:               approverRole_,
            members:                "?",
            restrictedSharedRoles:  "?",
            approved:               "?"
        });

        _contractRoles[contract_].roles[role_] = newRole_;

        emit CreatedRole( contract_, submitter_, role_ );
    }

    function setAdminRole( address contract_, address submitter_, bytes32 role_, bytes32 adminRole_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isRoot( contract_, submitter_ ) , "Submitter has insufficient permissions" );

        RoleData.Role storage roleData_ = _contractRoles[contract_].roles[role_];
        
        bytes32 previousAdminRole_ = roleData_.admin;
        roleData_.admin = adminRole_;

        emit SetAdminRole( contract_, submitter, role_, previousAdminRole, roleData_.admin );
    }

    function setApproverRole( address contract_, address submitter_, bytes32 role_, bytes32 approverRole_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isRoot( contract_, submitter_ ) , "Submitter has insufficient permissions" );

        RoleData.Role storage roleData_ = _contractRoles[contract_].roles[role_];
        
        bytes32 previousApproverRole_ = roleData_.approver;
        roleData_.approver = approverRole_;

        emit SetApproverRole( contract_, submitter_, role_, previousApproverRole_, roleData_.approver );
    }

    function addRestrictedSharedRole( address contract_, address submitter_, bytes32 role_, bytes32 restrictedSharedRole_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isRoot( contract_, submitter_ ) , "Submitter has insufficient permissions" );

        // TODO: What if you add a new role into this set and someone else has it? How do you check and undo their perms or just do not add it untill that is sorted?
        _contractRoles[contract_].roles[role_].restrictedSharedRoles.add( restrictedSharedRole_ );
        emit AddedRestrictedSharedRole( contract_, submitter_, role_, restrictedSharedRole_ );
    }

    function removeRestrictedSharedRole( address contract_, address submitter_, bytes32 role_, bytes32 restrictedSharedRole_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isRoot( contract_, submitter_ ) , "Submitter has insufficient permissions" );

        _contractRoles[contract_].roles[role_].restrictedSharedRoles.remove( restrictedSharedRole_ );
        emit RemovedRestrictedSharedRole( contract_, submitter_, role_, restrictedSharedRole_ );
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
        require( _contractExists(contract_), "Contract not in data store" );
        require( _isAdmin( contract_, role_, sender_ ),                         "RoleBasedAccessControl::sender must be an admin to grant" );
        require( !_hasRestrictedSharedRole( contract_, role_, account_ ),       "RoleBasedAccessControl::grantRole account has restrictedSharedRoles with role." );
        require( _isApprovedForRole( contract_, role_, account_ ),              "RoleBasedAccessControl::grantRole Address is not approved for role." );
                
        RoleData.Role storage roleData_ = _contractRoles[contract_].roles[role_];

        roleData_.members.add( account_ );

        emit RoleGranted( contract_, role_, account_, sender_ );

        // console.log("RoleBasedAccessControl: Granting %s role.", account);
        // console.log( "RoleBasedAccessControl::grantRole checking that %s is approved to have role.", account_ );
        // console.log( "RoleBasedAccessControl::grantRole checking that %s is admin to set role.", sender_ );
        // console.log( "RoleBasedAccessControl::grantRole checking that %s does not have any restricted shared roles for role.", account_ );
        // console.log( "RoleBasedAccessControl::grantRole Granting %s role.", account_ );
        // console.log( "RoleBasedAccessControl::grantRole Granted %s role.", account_ );
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
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isAdmin( contract_, role_, sender_ ), "AccessControl: sender must be an admin to remove" );
        require( _hasRole( contract_, role_, account_ ), "Account does not contain the role" );

        _contractRoles[contract_].roles[role_].members.remove( account_ );
        emit RoleRemoved( contract_, role_, account_, sender_ );
    }

    function approveForRole( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isApprover( contract_, role_, sender_ ), "RoleBasedAccessControl::approveForRole caller is not role approver." );

        contractRoles[contract_].roles[role_].approved[account_] = true;
        emit RoleApproved( contract_, role_, account_, approver_ );
    }

    function revokeApproval( address contract_, bytes32 role_, address account_, address sender_ ) external onlyPlatform() {
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _isApprover( contract_, role_, sender_ ), "RoleBasedAccessControl::revokeApproval caller is not role approver." );

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
        require( _contractExists( contract_ ), "Contract not in data store" );
        require( _hasRole( contract_, role_, Context._msgSender() ), "Account does not contain the role" );

        _contractRoles[contract_].roles[role_].members.remove( Context._msgSender() );
        emit RoleRenounced( contract_, role_, Context._msgSender() );
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _hasRole( contract_, role_, account_ );
    }

    function hasRestrictedSharedRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _hasRestrictedSharedRole( contract_, role_, account_ );
    }

    function isApprovedForRole( address contract_, bytes32 role_, address account_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _isApprovedForRole( contract_, role_, account_ );
    }

    function isRoleRestricted( address contract_, bytes32 role_, bytes32 restrictedRole_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _isRoleRestricted( contract_, role_, restrictedRole_ );
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setAdminRole}.
     */
    function getAdminRole( address contract_, bytes32 role_ ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _contractRoles[contract_].roles[role_].admin;
    }

    function getApproverRole( address contract_, bytes32 role_ ) external view returns ( bytes32 ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _contractRoles[contract_].roles[role_].approver;
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount( address contract_, bytes32 role_ ) external view returns ( uint256 ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _contractRoles[contract_].roles[role_].members.length();
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
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _contractRoles[contract_].roles[role_].members.at( index );
    }

    function hasAnyOfRoles( address contract_, address account_, bytes32[] roles_ ) external view returns ( bool ) {
        require( _contractExists( contract_ ), "Contract not in data store" );
        return _hasAnyOfRoles( contract_, account_, roles_ );
    }

    function _hasRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role_].members.contains( account_ );
    }

    function _isApprovedForRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[role_].approved[account_];
    }

    function _hasAnyOfRoles( address contract_, address account_, bytes32[] roles_ ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks
        for( uint256 iteration = 0; iteration <= roles_.length; iteration++ ) {
            if( _hasRole( contract_, roles_[iteration], account_ ) ) {
                return true;
            }
        }
        return false;
    }

    function _contractExists( address _contract ) private view returns ( bool ) {
        return _contractRoles[contract_] != address(0);
    }

    function _isRoot( address contract_, address account_ ) private view returns ( bool ) {
        return _contractRoles[contract_].roles[_contractRoles[contract_].root].members.contains( account_ );
    }

    function _isApprover( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role_].approver, account_ );
    }

    function _isAdmin( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        return _hasRole( contract_, _contractRoles[contract_].roles[role_].admin, account_ );
    }

    function _isRoleRestricted( address contract_, bytes32 role_, bytes32 restrictedRole_ ) private view returns ( bool ) {
        RoleData.Role storage roleData_ = _contractRoles[contract_].roles[role_];

        for( uint256 iteration = 0; iteration < roleData_.restrictedSharedRoles.length(); iteration++ ) {
            if ( roleData_.restrictedSharedRoles.at( iteration ) == restrictedRole_ ) {
                return true;
            }
        }

        return false;
    }

    function _hasRestrictedSharedRole( address contract_, bytes32 role_, address account_ ) private view returns ( bool ) {
        // TODO: May need to use when adding a new restricted role to perform checks
        RoleData.Role storage roleData_ = _contractRoles[contract_].roles[role_];

        for( uint256 iteration = 0; iteration < roleData_.restrictedSharedRoles.length(); iteration++ ) {
            if ( _contractRoles[contract_].roles[roleData_.restrictedSharedRoles.at( iteration )].members.contains( account_ ) ) {
                return true;
            }
        }

        return false;
    }
}