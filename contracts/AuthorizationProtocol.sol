// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.7.4;

// TODO: Who can call these functions e.g. registerContract
// TODO: Event emissions
// TODO: Wrap "msg.sender"
// TODO: Wrap "owner" with contract
// TODO: string memory to string calldata?
// TODO: Depending on implementation of RoleData role deletion may be possible (reasonable to implement)
// TODO: Consider how to actually add roles

import "../interfaces/IAuthorizationDatastore.sol";

/**
 * Should be deletaing role lookup and validation to the AuthroizationDatastore.
 * Acts as interface for other contracts to validate authorizations.
 * Should be an extensiion or reimplementation of TomeLockController.
 */
contract AuthorizationProtocol {

    address private _authorizationDatastore;
    address private _owner;

    modifier hasDatastore() {
        require( _authorizationDatastore != address(0), "Datastore has not been set to make calls" );
        _;
    }

    constructor() public {
        _owner = msg.sender;
    }
    
    function setDatastoreAddress( address authorizationDatastore_ ) external {
        require( _owner == msg.sender, "Owner only" );
        _authorizationDatastore = authorizationDatastore_;
    }

    function registerContract( address contract_, string memory rootRole, address rootAccount ) external hasDatastore() {
        bytes32 root = keccak256( abi.encode( rootRole ) );
        IAuthorizationDatastore( _authorizationDatastore ).registerContract( contract_, root, rootAccount );
    }

    function createRole( address contract_, string memory role, string memory adminRole, string memory approverRole ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 admin = keccak256( abi.encode( adminRole ) );
        bytes32 approver = keccak256( abi.encode( approverRole ) );
        
        IAuthorizationDatastore( _authorizationDatastore ).createRole( contract_, msg.sender, actualRole, admin, approver );
    }

    function setAdminRole( address contract_, string memory role, string memory adminRole ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 admin = keccak256( abi.encode( adminRole ) );
        
        IAuthorizationDatastore( _authorizationDatastore ).setAdminRole( contract_, msg.sender, actualRole, admin );
    }

    function setApproverRole( address contract_, string memory role, string memory approverRole ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 approver = keccak256( abi.encode( approverRole ) );
        
        IAuthorizationDatastore( _authorizationDatastore ).setApproverRole( contract_, msg.sender, actualRole, approver );
    }

    function addRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 restricted = keccak256( abi.encode( restrictedRole ) );
        
        IAuthorizationDatastore( _authorizationDatastore ).addRestrictedRole( contract_, msg.sender, actualRole, restricted );
    }
    
    function removeRestrictedRole( address contract_, string memory role, string memory restrictedRole ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 restricted = keccak256( abi.encode( restrictedRole ) );
        
        IAuthorizationDatastore( _authorizationDatastore ).removeRestrictedRole( contract_, msg.sender, actualRole, restricted );
    }

    function assignRole( address contract_, string memory role, address account ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        IAuthorizationDatastore( _authorizationDatastore ).assignRole( contract_, actualRole, account, msg.sender );
    }

    function removeRole( address contract_, string memory role, address account ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        IAuthorizationDatastore( _authorizationDatastore ).removeRole( contract_, actualRole, account, msg.sender );
    }

    function approveForRole( address contract_, string memory role, address account ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        IAuthorizationDatastore( _authorizationDatastore ).approveForRole( contract_, actualRole, account, msg.sender );
    }
    
    function revokeApproval( address contract_, string memory role, address account ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        IAuthorizationDatastore( _authorizationDatastore ).revokeApproval( contract_, actualRole, account, msg.sender );
    }

    function renounceRole( address contract_, string memory role ) external hasDatastore() {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        IAuthorizationDatastore( _authorizationDatastore ).renounceRole( contract_, actualRole );
    }
    
    function hasRole( address contract_, string memory role, address account ) external hasDatastore() view returns ( bool ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).hasRole( contract_, actualRole, account );
    }

    function hasRestrictedRole( address contract_, string memory role, address account ) external hasDatastore() view returns ( bool ) {        
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).hasRestrictedRole( contract_, actualRole, account );
    }

    function isApprovedForRole( address contract_, string memory role, address account ) external hasDatastore() view returns ( bool ) {        
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).isApprovedForRole( contract_, actualRole, account );
    }

    function isRoleRestricted( address contract_, string memory role, string memory restrictedRole ) external hasDatastore() view returns ( bool ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        bytes32 restricted = keccak256( abi.encode( restrictedRole ) );
        return IAuthorizationDatastore( _authorizationDatastore ).isRoleRestricted( contract_, actualRole, restricted );
    }

    function getAdminRole( address contract_, string memory role ) external hasDatastore() view returns ( bytes32 ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).getAdminRole( contract_, actualRole );
    }
    
    function getApproverRole( address contract_, string memory role ) external hasDatastore() view returns ( bytes32 ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).getApproverRole( contract_, actualRole );
    }

    function getRoleMemberCount( address contract_, string memory role ) external hasDatastore() view returns ( uint256 ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).getRoleMemberCount( contract_, actualRole );
    }

    function getRoleMember( address contract_, string memory role, uint256 index ) external hasDatastore() view returns ( address ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).getRoleMember( contract_, actualRole, index );
    }
    
    function isRoleCreated( address contract_, string memory role ) external hasDatastore() view returns ( bool ) {
        bytes32 actualRole = keccak256( abi.encode( role ) );
        return IAuthorizationDatastore( _authorizationDatastore ).isRoleCreated( contract_, actualRole );
    }
    
    function isContractRegistered( address contract_ ) external hasDatastore() view returns ( bool ) {
        return IAuthorizationDatastore( _authorizationDatastore ).isContractRegistered( contract_ );
    }

}


