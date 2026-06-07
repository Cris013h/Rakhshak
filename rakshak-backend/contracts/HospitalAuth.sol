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

    struct PreRegisteredStaff {
        string fullName;
        string idNumber;
        string post;
        string hospitalName;
        string department;
        bytes32 emailHash;
        bool exists;
        bool activated;
        uint256 registeredAt;
        address registeredBy;
    }

    mapping(string => Staff) private staffRegistry;
    mapping(string => PreRegisteredStaff) private preRegisteredStaff;
    mapping(string => string) private staffPublicKeys;

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

    event StaffPreRegistered(
        string idNumber,
        string post,
        uint256 timestamp
    );

    event StaffActivated(
        string idNumber,
        uint256 timestamp
    );

    event PublicKeyStored(
        string idNumber,
        uint256 timestamp
    );

    event RecordSignatureVerified(
        string idNumber,
        string recordHash,
        bool valid,
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

    function preRegisterStaff(
        string memory fullName,
        string memory idNumber,
        string memory post,
        string memory hospitalName,
        string memory department,
        bytes32 emailHash
    ) public {
        require(!preRegisteredStaff[idNumber].exists, "Already pre-registered");
        preRegisteredStaff[idNumber] = PreRegisteredStaff({
            fullName: fullName,
            idNumber: idNumber,
            post: post,
            hospitalName: hospitalName,
            department: department,
            emailHash: emailHash,
            exists: true,
            activated: false,
            registeredAt: block.timestamp,
            registeredBy: msg.sender
        });
        emit StaffPreRegistered(idNumber, post, block.timestamp);
    }

    function checkPreRegistered(
        string memory idNumber
    ) public view returns (bool exists, bool activated) {
        PreRegisteredStaff memory staff = preRegisteredStaff[idNumber];
        return (staff.exists, staff.activated);
    }

    function getPreRegisteredDetails(
        string memory idNumber
    ) public view returns (
        string memory fullName,
        string memory post,
        string memory hospitalName,
        string memory department
    ) {
        PreRegisteredStaff memory staff = preRegisteredStaff[idNumber];
        require(staff.exists, "Not pre-registered");
        return (staff.fullName, staff.post, staff.hospitalName, staff.department);
    }

    function activateStaff(
        string memory idNumber,
        bytes32 passwordHash
    ) public {
        PreRegisteredStaff storage preStaff = preRegisteredStaff[idNumber];
        require(preStaff.exists, "Not pre-registered");
        require(!preStaff.activated, "Already activated");
        require(!staffRegistry[idNumber].exists, "Staff already exists");

        preStaff.activated = true;

        staffRegistry[idNumber] = Staff({
            hospitalName: preStaff.hospitalName,
            post: preStaff.post,
            idNumber: idNumber,
            passwordHash: passwordHash,
            exists: true
        });

        emit StaffActivated(idNumber, block.timestamp);
    }

    function storePublicKey(
        string memory idNumber,
        string memory publicKey
    ) public {
        require(staffRegistry[idNumber].exists, "Staff not registered");
        staffPublicKeys[idNumber] = publicKey;
        emit PublicKeyStored(idNumber, block.timestamp);
    }

    function getPublicKey(
        string memory idNumber
    ) public view returns (string memory) {
        return staffPublicKeys[idNumber];
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

    function logRecordSignature(
        string memory idNumber,
        string memory recordHash,
        bool valid
    ) public {
        emit RecordSignatureVerified(idNumber, recordHash, valid, block.timestamp);
    }

    function staffExists(string memory idNumber) public view returns (bool) {
        return staffRegistry[idNumber].exists;
    }

    function getStaff(string memory idNumber) public view returns (Staff memory) {
        return staffRegistry[idNumber];
    }
}
