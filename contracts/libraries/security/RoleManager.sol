// SPDX-License-Identifier: AGPL-3.0-or-later
// pragma solidity 0.7.4;

// import "../../dataTypes/collections/AddressSet.sol";
// import "../../dataTypes/collections/Bytes32Set.sol";

// TODO: Documentation
// TODO: RoleManager - approved bool should be a struct containing data about who approved etc. for more information.
// TODO: Look into Address/Bytes32 sets -> replace with new structure if unnecessary. Fuck loops if we can use mappings and keep a counter
library RoleManager {

    using AddressSet for AddressSet.Set;
    using Bytes32Set for Bytes32Set.Set;

    struct Role {
        bytes32 admin;
        bytes32 approver;
        AddressSet.Set members;
        Bytes32Set.Set restrictedRoles;
        mapping(address => bool) approved;
    }
    
    // TODO: What else can I redesign?
    struct Account {
        mapping(bytes32 => bool) roles;
    }

    struct ContractRoles {
        bytes32 root;
        mapping(address => Account) accounts;
        mapping(bytes32 => Role) roles;
    }
    
    function registerRole( Role storage self, bytes32 role, address rootAccount ) internal {
        self.admin = role;
        self.members.add( rootAccount );
        self.approved[rootAccount] = true;
    }
    
    // TODO: This shit is retarded. Why can I not just access the (add etc.) function directly in the Datastore contract even if it is public in the AddressSet library?
    function assignRole( Role storage self, address member ) internal {
        self.members.add( member );
    }
    
    function removeRole( Role storage self, address member ) internal {
        self.members.remove( member );
    }
    
    function addRestrictedRole( Role storage self, bytes32 role ) internal {
        self.restrictedRoles.add( role );
    }
    
    function removeRestrictedRole( Role storage self, bytes32 role ) internal {
        self.restrictedRoles.remove( role );
    }
    
    function memberCount( Role storage self ) internal view returns ( uint256 ) {
        return self.members.length();
    }
    
    function restrictedCount( Role storage self ) internal view returns ( uint256 ) {
        return self.restrictedRoles.length();
    }
    
    function getMember( Role storage self, uint256 index ) internal view returns ( address ) {
        return self.members.at( index );
    }
    
    function getRestrictedRole( Role storage self, uint256 index ) internal view returns ( bytes32 ) {
        return self.restrictedRoles.at( index );
    }
    
    function isMember( Role storage self, address member ) internal view returns ( bool ) {
        return self.members.contains( member );
    }
    
    function createRole( Role storage self, bytes32 admin, bytes32 approver ) internal {
        self.admin = admin;
        self.approver = approver;
    }

}


