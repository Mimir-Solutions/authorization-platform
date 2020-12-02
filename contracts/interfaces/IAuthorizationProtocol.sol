// SPDX-License-Identifier: MIT
pragma solidity 0.7.4;

interface IAuthorizationProtocol {

    function registerContract( address contract_, string memory rootRole, address rootAccount ) external;
    
    function createRole( address contract_, string memory role, string memory adminRole, string memory approverRole ) external;
    
    function setAdminRole( address contract_, string memory role, string memory adminRole ) external;
    
    function setApproverRole( address contract_, string memory role, string memory approverRole ) external;
    
    function addRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external;
    
    function removeRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external;
    
    function assignRole( address contract_, string memory role, address account ) external;
    
    function removeRole( address contract_, string memory role, address account ) external;
    
    function approveForRole( address contract_, string memory role, address account ) external;
    
    function revokeApproval( address contract_, string memory role, address account ) external;
    
    function renounceRole( address contract_, string memory role ) external;
    
    function hasRole( address contract_, string memory role, address account ) external view returns ( bool );

    function hasRestrictedSharedRole( address contract_, string memory role, address account ) external view returns ( bool );
    
    function isApprovedForRole( address contract_, string memory role, address account ) external view returns ( bool );
    
    function isRoleRestricted( address contract_, string memory role, string memory restrictedRole ) external view returns ( bool );
    
    function getAdminRole( address contract_, string memory role ) external view returns ( bytes32 );
    
    function getApproverRole( address contract_, string memory role ) external view returns ( bytes32 );
    
    function getRoleMemberCount( address contract_, string memory role ) external view returns ( uint256 );
    
    function getRoleMember( address contract_, string memory role, uint256 index ) external view returns ( address );
    
    function isRoleCreated( address contract_, string memory role ) external view returns ( bool );

    function isContractRegistered( address contract_ ) external view returns ( bool );

}


