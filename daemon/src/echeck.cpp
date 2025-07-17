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
#line SOURCE_FILE("echeck.cpp")

#include "echeck.h"
#include <common/src/exec.h>
#include <common/src/builtin/path.h>
#include <QFileInfo>
#include <QTemporaryFile>
#include <QTextStream>
#include <QProcess>

namespace
{
    // Helper to write certificate data to a temporary file if needed
    QString ensureCertificateFile(const QString& certificateData)
    {
        // If it looks like a file path, use it directly
        if (QFileInfo::exists(certificateData) && !certificateData.contains("\n"))
        {
            return certificateData;
        }

        // Otherwise, write the certificate data to a temporary file
        QTemporaryFile tempFile;
        if (!tempFile.open())
        {
            qWarning() << "Failed to create temporary file for certificate data";
            return QString();
        }

        QTextStream stream(&tempFile);
        stream << certificateData;
        stream.flush();

        // Get the file path - tempFile will be deleted when it goes out of scope,
        // so we need to make sure it stays alive until after echeck is done
        QString filePath = tempFile.fileName();
        tempFile.setAutoRemove(false);

        return filePath;
    }
}

namespace ECheck
{
    SGXVerificationResult verifyCertificate(const QString& certificatePathOrData,
                                            const VerificationOptions& options)
    {
        QStringList args;

        // Handle certificate input
        QString certificatePath;
        bool fromStdin = false;

        if (certificatePathOrData.startsWith("-"))
        {
            fromStdin = true;
        }
        else
        {
            certificatePath = ensureCertificateFile(certificatePathOrData);
            if (certificatePath.isEmpty())
            {
                qWarning() << "Failed to process certificate data";
                return SGXVerificationResult{
                    false,
                    "Failed to process certificate data",
                    QString(),
                    QString(),
                    QString()
                };
            }
        }

        // Add optional arguments based on provided options
        if (options.verbose)
        {
            args << "-v";
        }

        if (options.quiet)
        {
            args << "--quiet";
        }

        if (options.raw)
        {
            args << "--raw";
        }

        if (options.json)
        {
            args << "--json";
        }

        if (!options.mrenclave.isEmpty())
        {
            args << "--mrenclave=" + options.mrenclave;
        }

        if (!options.mrsigner.isEmpty())
        {
            args << "--mrsigner=" + options.mrsigner;
        }

        // Add certificate path or stdin marker
        if (fromStdin)
        {
            args << "-";
        }
        else
        {
            args << certificatePath;
        }

        // Execute echeck
        QString output;
        int exitCode;
        qInfo() << "Args to be used " << args;
        if (fromStdin)
        {
            // Use QProcess to handle stdin input on all platforms
            QProcess process;
            process.start(Path::EcheckExecutable, args);
            
            if (!process.waitForStarted(5000)) {
                qWarning() << "Failed to start echeck process";
                return SGXVerificationResult{false, "Failed to start echeck process", QString(), QString(), QString()};
            }
            
            // Write certificate data to stdin
            process.write(certificatePathOrData.toUtf8());
            process.closeWriteChannel();
            
            if (!process.waitForFinished(30000)) { // 30 second timeout
                qWarning() << "echeck process timed out";
                process.terminate();
                return SGXVerificationResult{false, "echeck process timed out", QString(), QString(), QString()};
            }
            
            exitCode = process.exitCode();
            output = QString::fromUtf8(process.readAllStandardOutput());
            
            // Log any stderr output
            QString errorOutput = QString::fromUtf8(process.readAllStandardError());
            if (!errorOutput.isEmpty()) {
                qWarning() << "echeck stderr:" << errorOutput;
            }
        }
        else
        {
            // Normal file-based execution using QProcess
            QProcess process;
            process.start(Path::EcheckExecutable, args);
            
            if (!process.waitForFinished(30000)) { // 30 second timeout
                qWarning() << "echeck process timed out";
                process.terminate();
                return SGXVerificationResult{false, "echeck process timed out", QString(), QString(), QString()};
            }
            
            exitCode = process.exitCode();
            output = QString::fromUtf8(process.readAllStandardOutput());
            
            // Log any stderr output
            QString errorOutput = QString::fromUtf8(process.readAllStandardError());
            if (!errorOutput.isEmpty()) {
                qWarning() << "echeck stderr:" << errorOutput;
            }
        }

        // No temporary files to clean up anymore

        qInfo() << "Output received: "<< output;

        // Parse output to get MRENCLAVE and MRSIGNER values
        QString mrenclave, mrsigner, productID;

        if (options.raw || options.json)
        {
            // Parse the structured output
            // This is simplified - real parsing would depend on the exact format
            if (options.json)
            {
                // Simplistic JSON parsing - in a real implementation, use a proper JSON parser
                QRegularExpression reEnclave("\"mrenclave\"\\s*:\\s*\"([0-9a-fA-F]+)\"");
                QRegularExpression reSigner("\"mrsigner\"\\s*:\\s*\"([0-9a-fA-F]+)\"");
                QRegularExpression reProductID("\"productid\"\\s*:\\s*\"([0-9]+)\"");

                auto matchEnclave = reEnclave.match(output);
                auto matchSigner = reSigner.match(output);
                auto matchProductID = reProductID.match(output);

                if (matchEnclave.hasMatch()) mrenclave = matchEnclave.captured(1);
                if (matchSigner.hasMatch()) mrsigner = matchSigner.captured(1);
                if (matchProductID.hasMatch()) productID = matchProductID.captured(1);
            }
            else
            {
                // Raw key=value parsing
                QRegularExpression reKeyValue("(\\w+)=([^\\s]+)");
                auto matchIterator = reKeyValue.globalMatch(output);

                while (matchIterator.hasNext())
                {
                    auto match = matchIterator.next();
                    QString key = match.captured(1).toLower();
                    QString value = match.captured(2);

                    if (key == "mrenclave") mrenclave = value;
                    else if (key == "mrsigner") mrsigner = value;
                    else if (key == "productid") productID = value;
                }
            }
        }
        else
        {
            // Parse the regular output format
            QRegularExpression reEnclave("MRENCLAVE:\\s*([0-9a-fA-F]+)", QRegularExpression::CaseInsensitiveOption);
            QRegularExpression reSigner("MRSIGNER:\\s*([0-9a-fA-F]+)", QRegularExpression::CaseInsensitiveOption);
            QRegularExpression reProductID("Product ID:\\s*([0-9]+)", QRegularExpression::CaseInsensitiveOption);

            auto matchEnclave = reEnclave.match(output);
            auto matchSigner = reSigner.match(output);
            auto matchProductID = reProductID.match(output);

            if (matchEnclave.hasMatch()) mrenclave = matchEnclave.captured(1);
            if (matchSigner.hasMatch()) mrsigner = matchSigner.captured(1);
            if (matchProductID.hasMatch()) productID = matchProductID.captured(1);
        }

        return SGXVerificationResult{
            exitCode == 0,
            output,
            mrenclave,
            mrsigner,
            productID
        };
    }

    bool quickVerify(const QString& certificatePathOrData, const QString& expectedMrenclave,
                     const QString& expectedMrsigner)
    {
        VerificationOptions options;
        options.quiet = true;

        if (!expectedMrenclave.isEmpty())
        {
            options.mrenclave = expectedMrenclave;
        }

        if (!expectedMrsigner.isEmpty())
        {
            options.mrsigner = expectedMrsigner;
        }

        auto result = verifyCertificate(certificatePathOrData, options);
        return result.success;
    }

    QString getVersion()
    {
        QString output;

#if defined(Q_OS_UNIX)
        // On Unix systems we can use cmdWithOutput
        output = Exec::cmdWithOutput(Path::EcheckExecutable, {"--version"});
#else
    // On Windows, use a temporary file for output
    QTemporaryFile outputFile;
    if (outputFile.open()) {
        outputFile.close();

        // Redirect output to the temp file
        QStringList redirectArgs = {"--version", ">", outputFile.fileName()};

        Exec::cmd(Path::EcheckExecutable, redirectArgs);

        // Read the output file
        if (outputFile.open()) {
            QTextStream outStream(&outputFile);
            output = outStream.readAll();
            outputFile.close();
        }
    }
#endif

        return output.trimmed();
    }
} // namespace ECheck
