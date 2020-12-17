// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity 0.8.0;

import "../../dependencies/holyzeppelin/contracts/datatypes/collections/EnumerableSet.sol";

// TODO: Better description
// TODO: RoleData - roleApproval bool should be a struct containing data about who approved etc. for more information .

/**
 * @notice Datatype for reuse in the authroization system.
 */
library RoleData {

    using EnumerableSet for EnumerableSet.Set;
    using EnumerableSet for EnumerableSet.Set;

    struct Role {
        bytes32 admin;
        bytes32 approver;
        EnumerableSet.AddressSet members;
        EnumerableSet.Bytes32Set restrictedRoles;
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

}