// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract HospitalAuth {
    struct Staff {
        string hospitalName;
        string post;
        string idNumber;
        bytes32 passwordHash;
        bool exists;
    }

    mapping(string => Staff) private staffRegistry;

    event LoginAttempt(
        string idNumber,
        string hospitalName,
        bool success,
        uint256 timestamp
    );

    event DataAccessed(
        string idNumber,
        string hospitalName,
        string post,
        string dataType,
        uint256 timestamp
    );

    event SuspiciousActivity(
        string idNumber,
        string activityType,
        uint256 timestamp
    );

    function registerStaff(
        string memory hospitalName,
        string memory post,
        string memory idNumber,
        bytes32 passwordHash
    ) public {
        require(!staffRegistry[idNumber].exists, "Staff already exists");
        staffRegistry[idNumber] = Staff({
            hospitalName: hospitalName,
            post: post,
            idNumber: idNumber,
            passwordHash: passwordHash,
            exists: true
        });
    }

    function verifyStaff(
        string memory hospitalName,
        string memory post,
        string memory idNumber,
        bytes32 passwordHash
    ) public returns (bool) {
        Staff memory staff = staffRegistry[idNumber];
        bool success = staff.exists &&
            keccak256(bytes(staff.hospitalName)) == keccak256(bytes(hospitalName)) &&
            keccak256(bytes(staff.post)) == keccak256(bytes(post)) &&
            staff.passwordHash == passwordHash;

        emit LoginAttempt(idNumber, hospitalName, success, block.timestamp);
        return success;
    }

    function logDataAccess(
        string memory idNumber,
        string memory hospitalName,
        string memory post,
        string memory dataType
    ) public {
        emit DataAccessed(
            idNumber,
            hospitalName,
            post,
            dataType,
            block.timestamp
        );
    }

    function logSuspiciousActivity(
        string memory idNumber,
        string memory activityType
    ) public {
        emit SuspiciousActivity(idNumber, activityType, block.timestamp);
    }

    function staffExists(string memory idNumber) public view returns (bool) {
        return staffRegistry[idNumber].exists;
    }

    function getStaff(string memory idNumber) public view returns (Staff memory) {
        return staffRegistry[idNumber];
    }
}
