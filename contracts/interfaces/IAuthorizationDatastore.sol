// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.5;

interface IAuthorizationDatastore {
    
    function registerContract( address contract_, bytes32 rootRole, address rootAccount ) external;
    
    function createRole( address contract_, address submitter, bytes32 role, bytes32 adminRole, bytes32 approverRole ) external;
    
    function setAdminRole( address contract_, address submitter, bytes32 role, bytes32 adminRole ) external;
    
    function setApproverRole( address contract_, address submitter, bytes32 role, bytes32 approverRole ) external;
    
    function addRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external;
    
    function removeRestrictedRole( address contract_, address submitter, bytes32 role, bytes32 restrictedRole ) external;
    
    function assignRole( address contract_, bytes32 role, address account, address sender ) external;

    function removeRole( address contract_, bytes32 role, address account, address sender ) external;

    function approveForRole( address contract_, bytes32 role, address account, address sender ) external;

    function revokeApproval( address contract_, bytes32 role, address account, address sender ) external;

    function renounceRole( address contract_, bytes32 role ) external;

    function hasRole( address contract_, bytes32 role, address account ) external view returns ( bool );

    function hasRestrictedRole( address contract_, bytes32 role, address account ) external view returns ( bool );

    function isApprovedForRole( address contract_, bytes32 role, address account ) external view returns ( bool );

    function isRoleRestricted( address contract_, bytes32 role, bytes32 restrictedRole ) external view returns ( bool );

    function getAdminRole( address contract_, bytes32 role ) external view returns ( bytes32 );

    function getApproverRole( address contract_, bytes32 role ) external view returns ( bytes32 );

    function getRoleMemberCount( address contract_, bytes32 role ) external view returns ( uint256 );

    function getRoleMember( address contract_, bytes32 role, uint256 index ) external view returns ( address );

    function isRoleCreated( address contract_, bytes32 role ) external view returns ( bool );

    function isContractRegistered( address contract_ ) external view returns ( bool );

}

