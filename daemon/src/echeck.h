// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include <common/src/common.h>
#line HEADER_FILE("echeck.h")

#ifndef ECHECK_H
#define ECHECK_H

#include <QString>

/**
 * @brief ECheck provides C++ wrapper functions for the echeck SGX verification tool
 * 
 * This module allows easy verification of Intel SGX quotes embedded in X.509 certificates
 * by providing a C++ interface to the echeck command-line tool.
 */
namespace ECheck {

/**
 * @brief Options for configuring SGX verification behavior
 */
struct VerificationOptions {
    bool verbose = false;   ///< Enable verbose output
    bool quiet = false;     ///< Quiet mode (only errors printed)
    bool raw = false;       ///< Output in machine-readable format
    bool json = false;      ///< Output in JSON format
    QString mrenclave;      ///< Expected MRENCLAVE value (64 hex chars)
    QString mrsigner;       ///< Expected MRSIGNER value (64 hex chars)
};

/**
 * @brief Results from an SGX verification operation
 */
struct SGXVerificationResult {
    bool success = false;     ///< Whether verification succeeded
    QString output;           ///< Raw output from echeck
    QString mrenclave;        ///< Extracted MRENCLAVE value (if available)
    QString mrsigner;         ///< Extracted MRSIGNER value (if available)
    QString productID;        ///< Extracted Product ID (if available)
    
    /**
     * @brief Converts the verification result to a formatted string
     * 
     * @param verbose Whether to include detailed output in the string
     * @return QString Formatted string representation of the verification result
     */
    QString toString(bool verbose = false) const {
        QString result;
        QTextStream stream(&result);
        
        stream << "SGX Verification: " << (success ? "SUCCESS" : "FAILED") << "\n";
        
        if (!mrenclave.isEmpty())
            stream << "MRENCLAVE: " << mrenclave << "\n";
            
        if (!mrsigner.isEmpty())
            stream << "MRSIGNER: " << mrsigner << "\n";
            
        if (!productID.isEmpty())
            stream << "Product ID: " << productID << "\n";
            
        if (verbose && !output.isEmpty())
            stream << "Output: " << output << "\n";
            
        return result;
    }
};

/**
 * @brief Verify an SGX certificate with customizable options
 * 
 * @param certificatePathOrData Path to a certificate file, raw PEM data, or "-" for stdin
 * @param options Verification options including expected values and output format
 * @return SGXVerificationResult containing success status and extracted values
 */
SGXVerificationResult verifyCertificate(const QString& certificatePathOrData, 
                                      const VerificationOptions& options = VerificationOptions());

/**
 * @brief Quick verification of an SGX certificate against expected values
 * 
 * This is a simplified version of verifyCertificate that only returns success/failure.
 * 
 * @param certificatePathOrData Path to a certificate file, raw PEM data, or "-" for stdin
 * @param expectedMrenclave Expected MRENCLAVE value (empty to skip check)
 * @param expectedMrsigner Expected MRSIGNER value (empty to skip check)
 * @return bool True if verification succeeded, false otherwise
 */
bool quickVerify(const QString& certificatePathOrData, 
                 const QString& expectedMrenclave = QString(), 
                 const QString& expectedMrsigner = QString());

/**
 * @brief Get the version information of the echeck tool
 * 
 * @return QString Version string
 */
QString getVersion();

/**
 * @brief Convert an SGX verification result to a formatted string
 * 
 * This is a utility function that calls the toString() method of SGXVerificationResult.
 * It's provided as a convenience for functional-style programming.
 * 
 * @param result The verification result to format
 * @param verbose Whether to include detailed output in the string
 * @return QString Formatted string representation of the verification result
 */
inline QString formatSGXResult(const SGXVerificationResult& result, bool verbose = false) {
    return result.toString(verbose);
}

} // namespace ECheck

#endif // ECHECK_H