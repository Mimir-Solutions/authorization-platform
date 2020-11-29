// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

// TODO: Who can call these functions e.g. registerContract
// TODO: Event emissions
// TODO: Assuming datastore interface, need to implement since I'm only calling a function on the supposed interface store atm
// TODO: Wrap msg.sender
// TODO: String to bytes32 conversion

/**
 * Should be deletaing role lookup and validation to the AuthroizationDatastore.
 * Acts as interface for other contracts to validate authorizations.
 * Should be an extensiion or reimplementation of TomeLockController.
 */
contract AuthorizationProtocol {

    // TODO: Should be an Interface 
    address private authorizationDatastore;

    constructor() {}

    function registerContract( address contract_, string memory rootRole, address rootAccount ) external {
        bytes32 root = keccak256( rootRole );
        authorizationDatastore.registerContract( contract_, root, rootAccount );
    }

    function createRole( address contract_, string memory role, string memory adminRole, string memory approverRole ) external {
        bytes32 actualRole = keccak256( role );
        bytes32 admin = keccak256( adminRole );
        bytes32 approver = keccak256( approverRole );
        
        authorizationDatastore.createRole( contract_, msg.sender, actualRole, admin, approver );
    }

    function setAdminRole( address contract_, string memory role, string memory adminRole ) external {
        bytes32 actualRole = keccak256( role );
        bytes32 admin = keccak256( adminRole );
        
        authorizationDatastore.setAdminRole( contract_, msg.sender, actualRole, admin );
    }

    function setApproverRole( address contract_, string memory role, string memory approverRole ) external {
        bytes32 actualRole = keccak256( role);
        bytes32 approver = keccak256( approverRole );
        
        authorizationDatastore.setApproverRole( contract_, msg.sender, actualRole, approver );
    }

    function addRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external {
        bytes32 actualRole = keccak256( role );
        bytes32 restricted = keccak256( restrictedRole );
        
        authorizationDatastore.addRestrictedRole( contract_, msg.sender, actualRole, restricted );
    }
    
    function removeRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external {
        bytes32 actualRole = keccak256( role );
        bytes32 restricted = keccak256( restrictedRole );
        
        authorizationDatastore.removeRestrictedRole( contract_, msg.sender, actualRole, restricted );
    }

    function assignRole( address contract_, string memory role, address account ) external {
        bytes32 actualRole = keccak256( role );
        authorizationDatastore.assignRole( contract_, actualRole, account, msg.sender );
    }

    function removeRole( address contract_, string memory role, address account ) external {
        bytes32 actualRole = keccak256( role );
        authorizationDatastore.removeRole( contract_, actualRole, account, msg.sender );
    }

    function approveForRole( address contract_, string memory role, address account ) external {
        bytes32 actualRole = keccak256( role );
        authorizationDatastore.approveForRole( contract_, actualRole, account, msg.sender );
    }
    
    function revokeApproval( address contract_, string memory role, address account ) external {
        bytes32 actualRole = keccak256( role );
        authorizationDatastore.revokeApproval( contract_, actualRole, account, msg.sender );
    }

    function renounceRole( address contract_, string memory role ) external {
        // TODO: This can currently be called directly from the store... but should it?
        bytes32 actualRole = keccak256( role );
        authorizationDatastore.renounceRole( contract_, actualRole );
    }
    
    function hasRole( address contract_, string memory role, address account ) external view returns ( bool ) {
        // TODO: This can currently be called directly from the store... but should it?
        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.hasRole( contract_, actualRole, account );
    }

    function hasRestrictedSharedRole( address contract_, string memory role, address account ) external view returns ( bool ) {
        // TODO: This can currently be called directly from the store... but should it?
        
        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.hasRestrictedSharedRole( contract_, actualRole, account );
    }

    function isApprovedForRole( address contract_, string memory role, address account ) external view returns ( bool ) {
        // TODO: This can currently be called directly from the store... but should it?
        
        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.isApprovedForRole( contract_, actualRole, account );
    }

    function isRoleRestricted( address contract_, string memory role, string memory restrictedRole ) external view returns ( bool ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32 actualRole = keccak256( role );
        bytes32 restricted = keccak256( restrictedRole );

        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.isRoleRestricted( contract_, actualRole, restricted );
    }

    function getAdminRole( address contract_, string memory role ) external view returns ( bytes32 ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.getAdminRole( contract_, actualRole );
    }
    
    function getApproverRole( address contract_, string memory role ) external view returns ( bytes32 ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.getApproverRole( contract_, actualRole );
    }

    function getRoleMemberCount( address contract_, string memory role ) external view returns ( uint256 ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.getRoleMemberCount( contract_, actualRole );
    }

    function getRoleMember( address contract_, string memory role, uint256 index ) external view returns ( address ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32 actualRole = keccak256( role );
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.getRoleMember( contract_, actualRole, index );
    }

    function hasAnyOfRoles( address contract_, address account, string[] calldata roles ) external view returns ( bool ) {
        // TODO: This can currently be called directly from the store... but should it?

        bytes32[] memory actualRoles;
        
        for ( uint256 iteration = 0; iteration <= roles.length; iteration++ ) {
            bytes32 role = keccak256( roles[iteration] );
            actualRoles.push( role );
        }
        
        // TODO: Depends on how it is written but I may be able to directly return the value or I must decode
        return authorizationDatastore.hasAnyOfRoles( contract_, account, actualRoles );
    }

}


