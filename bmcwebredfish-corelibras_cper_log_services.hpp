#pragma once

#include <systemd/sd-journal.h>
#include <unistd.h>

#include <app.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/beast/http.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/system/linux_error.hpp>
#include <error_messages.hpp>

#include <filesystem>
#include <span>
#include <string_view>
#include <variant>
#include <sstream>

extern "C" {
    #include <json-c/json.h>
    #include <cper-parse.h>
}

namespace redfish
{

#ifdef BMCWEB_ENABLE_REDFISH_RAS_LOGGER

inline void getRasLogDumpServiceInfo(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::string dumpPath = "/redfish/v1/Systems/system/LogServices/RasEvent";
    std::string overWritePolicy = "Unknown";

    asyncResp->res.jsonValue["@odata.id"] = dumpPath;
    asyncResp->res.jsonValue["@odata.type"] = "#LogService.v1_2_0.LogService";
    asyncResp->res.jsonValue["Name"] = "Dump LogService";
    asyncResp->res.jsonValue["Description"] = "Ras Event Dump LogService";
    asyncResp->res.jsonValue["Id"] = std::filesystem::path(dumpPath).filename();
    asyncResp->res.jsonValue["OverWritePolicy"] = std::move(overWritePolicy);

    std::pair<std::string, std::string> redfishDateTimeOffset =
        crow::utility::getDateTimeOffsetNow();
    asyncResp->res.jsonValue["DateTime"] = redfishDateTimeOffset.first;
    asyncResp->res.jsonValue["DateTimeLocalOffset"] =
        redfishDateTimeOffset.second;

    asyncResp->res.jsonValue["Entries"]["@odata.id"] = dumpPath + "/Entries";
    asyncResp->res.jsonValue["Actions"]["#LogService.ClearLog"]["target"] =
        dumpPath + "/Actions/LogService.ClearLog";

}

inline void parseDumpEntryFromDbusObject(
    const dbus::utility::ManagedObjectType::value_type& object,
    std::string& dumpStatus, uint64_t& timestampUs,
    std::string& entryType, std::string& primaryLogId,
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{

    for (const auto& interfaceMap : object.second)
    {
        if (interfaceMap.first == "xyz.openbmc_project.Common.Progress")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Status")
                {
                    const auto* status =
                        std::get_if<std::string>(&propertyMap.second);
                    if (status == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    dumpStatus = *status;
                }
            }
        }
        else if (interfaceMap.first == "xyz.openbmc_project.Time.EpochTime")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Elapsed")
                {
                    const uint64_t* usecsTimeStamp =
                        std::get_if<uint64_t>(&propertyMap.second);
                    if (usecsTimeStamp == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    timestampUs = *usecsTimeStamp;
                    break;
                }
            }
        }
        else if (interfaceMap.first ==
                 "xyz.openbmc_project.Dump.Entry.FaultLog")
        {
            for (const auto& propertyMap : interfaceMap.second)
            {
                if (propertyMap.first == "Type")
                {
                    const std::string* entryTypePtr =
                        std::get_if<std::string>(&propertyMap.second);
                    if (entryTypePtr == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    if (*entryTypePtr ==
                        "xyz.openbmc_project.Dump.Entry.FaultLog.FaultDataType.Crashdump")
                    {
                        entryType = "Crashdump";
                    }
                    else if (
                        *entryTypePtr ==
                        "xyz.openbmc_project.Dump.Entry.FaultLog.FaultDataType.CPER")
                    {
                        entryType = "CPER";
                    }
                }
                else if (propertyMap.first == "PrimaryLogId")
                {
                    const std::string* primaryLogIdPtr =
                        std::get_if<std::string>(&propertyMap.second);
                    if (primaryLogIdPtr == nullptr)
                    {
                        messages::internalError(asyncResp->res);
                        break;
                    }
                    primaryLogId = *primaryLogIdPtr;
                }
            }
        }
    }
}

inline void getFaultDumpOverviewById(nlohmann::json& thisEntry,
                                     const std::string& entryID)
{
    std::filesystem::path loc("/var/lib/phosphor-debug-collector/faultlogs/" +
                              entryID);
    if (!std::filesystem::exists(loc))
    {
        BMCWEB_LOG_ERROR << loc << "Not found";
        thisEntry["Message"] = "Not found";
        return;
    }

    std::ifstream faultlogFile(loc.string());
    if (!faultlogFile.is_open())
    {
        BMCWEB_LOG_ERROR << loc << " Open Fail";
        thisEntry["Message"] = "Not found";
        return;
    }

    nlohmann::json j;
    faultlogFile >> j;

    thisEntry["Message"] =
        j.contains("Message") ? j["Message"].get<std::string>() : "Unknown";

    thisEntry["Severity"] =
        j.contains("Severity") ? j["Severity"].get<std::string>() : "OK";

    if (j.contains("CperTimestamp"))
    {
        thisEntry["Created"] = j["CperTimestamp"].get<std::string>();
    }

    if (j.contains("MessageArgs"))
    {
        nlohmann::json& entriesArray =  thisEntry["MessageArgs"];
        entriesArray = nlohmann::json::array();

        std::istringstream mesgArgs;
        mesgArgs.str(j["MessageArgs"].get<std::string>());
        for(std::string arg; std::getline(mesgArgs,arg,'#');)
        {
           entriesArray.push_back(arg);
        }
    }

    faultlogFile.close();
    return;
}

inline void getRasLogDumpEntryCollection(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp)
{
    std::string entriesPath =
        "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/";

    crow::connections::systemBus->async_method_call(
        [asyncResp, entriesPath](const boost::system::error_code ec,
                                 dbus::utility::ManagedObjectType& resp) {
            if (ec)
            {
                BMCWEB_LOG_ERROR << "DumpEntry resp_handler got error " << ec;
                messages::internalError(asyncResp->res);
                return;
            }

            // Remove ending slash
            std::string odataIdStr = entriesPath;
            if (!odataIdStr.empty())
            {
                odataIdStr.pop_back();
            }

            asyncResp->res.jsonValue["@odata.type"] =
                "#LogEntryCollection.LogEntryCollection";
            asyncResp->res.jsonValue["@odata.id"] = std::move(odataIdStr);
            asyncResp->res.jsonValue["Name"] = "FaultLog Dump Entries";
            asyncResp->res.jsonValue["Description"] =
                "Collection of FaultLog Dump Entries";

            nlohmann::json& entriesArray = asyncResp->res.jsonValue["Members"];
            entriesArray = nlohmann::json::array();
            std::string dumpEntryPath("/xyz/openbmc_project/dump/faultlog/entry/");

            std::sort(resp.begin(), resp.end(),
                      [](const auto& l, const auto& r) {
                          return AlphanumLess<std::string>()(
                              l.first.filename(), r.first.filename());
                      });

            for (auto& object : resp)
            {
                if (object.first.str.find(dumpEntryPath) == std::string::npos)
                {
                    continue;
                }
                uint64_t timestampUs = 0;
                std::string dumpStatus;
                std::string primaryLogId;
                std::string entryType;
                nlohmann::json thisEntry;

                std::string entryID = object.first.filename();
                if (entryID.empty())
                {
                    continue;
                }

                parseDumpEntryFromDbusObject(object, dumpStatus,
                                             timestampUs, entryType,
                                             primaryLogId, asyncResp);

                if (dumpStatus !=
                        "xyz.openbmc_project.Common.Progress.OperationStatus.Completed" &&
                    !dumpStatus.empty() && entryType != "CPER")
                {
                    // Dump status is not Complete, no need to enumerate
                    continue;
                }

                thisEntry["@odata.type"] = "#LogEntry.v1_10_0.LogEntry";
                thisEntry["@odata.id"] = entriesPath + entryID;
                thisEntry["Id"] = entryID;
                thisEntry["EntryType"] = "Event";
                thisEntry["Name"] = "Ras Event Dump Entry";
                thisEntry["Created"] =
                    crow::utility::getDateTimeUint(timestampUs / 1000 / 1000);

                getFaultDumpOverviewById(thisEntry, entryID);
                thisEntry["EntryType"] = "Event";
                thisEntry["DiagnosticDataType"] = "CPER";

                thisEntry["AdditionalDataURI"] =
                    "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/" +
                    primaryLogId + "/attachment";
                entriesArray.push_back(std::move(thisEntry));
            }
            asyncResp->res.jsonValue["Members@odata.count"] =
                entriesArray.size();
        },
        "xyz.openbmc_project.Dump.Manager", "/xyz/openbmc_project/dump",
        "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
}

inline void
    getFaultDumpEntryById(const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                          const std::string& entryID)
{
    std::string dumpEntryPath =
        "/xyz/openbmc_project/dump/faultlog/entry/" + entryID;

    crow::connections::systemBus->async_method_call(
        [asyncResp, entryID](const boost::system::error_code ec,
                             dbus::utility::DBusPropertiesMap& resp) {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(
                    asyncResp->res, "Fault Dump EventLog Entry", entryID);
                return;
            }

            if (ec)
            {
                BMCWEB_LOG_ERROR << "DumpEntry resp_handler got error " << ec;
                messages::internalError(asyncResp->res);
                return;
            }

            std::string entriesPath(
                "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/");

            uint64_t timestampUs = 0;
            std::string dumpStatus;
            std::string primaryLogId;
            std::string entryType;

            for (auto& propertyMap : resp)
            {
                if (propertyMap.first == "Status")
                {
                    const std::string* value =
                        std::get_if<std::string>(&propertyMap.second);
                    if (value != nullptr)
                    {
                        dumpStatus = *value;
                    }
                }
                else if (propertyMap.first == "Elapsed")
                {
                    const uint64_t* value =
                        std::get_if<uint64_t>(&propertyMap.second);
                    if (value != nullptr)
                    {
                        timestampUs = *value;
                    }
                }
                else if (propertyMap.first == "PrimaryLogId")
                {
                    const std::string* value =
                        std::get_if<std::string>(&propertyMap.second);
                    if (value != nullptr)
                    {
                        primaryLogId = *value;
                    }
                }
                else if (propertyMap.first == "Type")
                {
                    const std::string* entryTypePtr =
                        std::get_if<std::string>(&propertyMap.second);
                    if (entryTypePtr != nullptr &&
                        *entryTypePtr ==
                            "xyz.openbmc_project.Dump.Entry.FaultLog.FaultDataType.CPER")
                    {
                        entryType = "CPER";
                    }
                }
            }

            if (dumpStatus !=
                    "xyz.openbmc_project.Common.Progress.OperationStatus.Completed" &&
                !dumpStatus.empty() && entryType != "CPER")
            {
                // Dump status is not Complete, no need to enumerate
                BMCWEB_LOG_ERROR << "Can't find Dump Entry";
                messages::internalError(asyncResp->res);
                return;
            }

            nlohmann::json& thisEntry = asyncResp->res.jsonValue;
            thisEntry["@odata.type"] = "#LogEntry.v1_10_0.LogEntry";
            thisEntry["@odata.id"] = entriesPath + entryID;
            thisEntry["Id"] = entryID;
            thisEntry["EntryType"] = "Event";
            thisEntry["Name"] = "Ras Event Dump Entry";
            thisEntry["Created"] =
                crow::utility::getDateTimeUint(timestampUs / 1000 / 1000);

            getFaultDumpOverviewById(thisEntry, entryID);
            thisEntry["EntryType"] = "Event";
            thisEntry["DiagnosticDataType"] = "CPER";

            thisEntry["AdditionalDataURI"] =
                "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/" +
                primaryLogId + "/attachment";
        },
        "xyz.openbmc_project.Dump.Manager", dumpEntryPath,
        "org.freedesktop.DBus.Properties", "GetAll", "");
}

inline void deleteFaultDumpEntryById(
    const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
    const std::string& entryID)
{
    auto respHandler = [asyncResp,
                        entryID](const boost::system::error_code ec) {
        BMCWEB_LOG_DEBUG << "Dump Entry doDelete callback: Done";
        if (ec)
        {
            if (ec.value() == EBADR)
            {
                messages::resourceNotFound(asyncResp->res, "LogEntry", entryID);
                return;
            }
            BMCWEB_LOG_ERROR << "Dump (DBus) doDelete respHandler got error "
                             << ec << " entryID=" << entryID;
            messages::internalError(asyncResp->res);
            return;
        }
    };
    crow::connections::systemBus->async_method_call(
        respHandler, "xyz.openbmc_project.Dump.Manager",
        "/xyz/openbmc_project/dump/Fault/entry/" + entryID,
        "xyz.openbmc_project.Object.Delete", "Delete");
}

inline void requestRoutesRasLogDumpService(App& app)
{
    BMCWEB_ROUTE(app, "/redfish/v1/Systems/system/LogServices/RasEvent/")
        .privileges(redfish::privileges::getLogService)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                getRasLogDumpServiceInfo(asyncResp);
            });
}

inline void requestRoutesRasLogDumpEntryCollection(App& app)
{
    BMCWEB_ROUTE(app,
                 "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/")
        .privileges(redfish::privileges::getLogEntryCollection)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                getRasLogDumpEntryCollection(asyncResp);
            });
}

inline void requestRoutesRasLogDumpEntry(App& app)
{
    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/<str>/")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& dumpId) {
                getFaultDumpEntryById(asyncResp, dumpId);
            });

    BMCWEB_ROUTE(
        app, "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/<str>/")
        .privileges(redfish::privileges::deleteLogEntry)
        .methods(boost::beast::http::verb::delete_)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& dumpId) {
                deleteDumpEntry(asyncResp, dumpId, "FaultLog");
            });
}

inline void requestRoutesRasLogDumpClear(App& app)
{
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/system/LogServices/RasEvent/Actions/LogService.ClearLog/")
        .privileges(redfish::privileges::postLogService)
        .methods(boost::beast::http::verb::post)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp) {
                clearDump(asyncResp, "FaultLog");
            });
}

inline json_object* getCperJsonObject(size_t indexCper,
                                      const std::string& filePath,
                                      bool isSingle)
{
    // Convert to JSON.
    FILE* cperFile = fopen(filePath.c_str(), "r");
    json_object* cperIR = cper_to_ir(cperFile);
    fclose(cperFile);

    if (isSingle)
    {
        json_object* header = json_object_object_get(cperIR, "header");

        // Gets a single CPER based on indexCper
        json_object* singleSectionDescriptor = json_object_array_get_idx(
            json_object_object_get(cperIR, "sectionDescriptors"), indexCper);
        json_object* singleSection = json_object_array_get_idx(
            json_object_object_get(cperIR, "sections"), indexCper);

        if(singleSectionDescriptor == NULL || singleSection == NULL)
        {
            return NULL;
        }
        // Generates a new single CPER containing the header
        json_object* newSectionDescriptorIR = json_object_new_array();
        json_object* newSectionsIR = json_object_new_array();

        json_object_array_add(newSectionDescriptorIR, singleSectionDescriptor);
        json_object_array_add(newSectionsIR, singleSection);

        json_object* newCper = json_object_new_object();
        json_object_object_add(newCper, "header", header);
        json_object_object_add(newCper, "sectionDescriptors",
                               newSectionDescriptorIR);
        json_object_object_add(newCper, "sections", newSectionsIR);

        return newCper;
    }

    return cperIR;
}

#define CPER_LOG_DIR "/var/log/ras/"

inline void requestRoutesRasLogDownload(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/<str>/attachment")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [&app](const crow::Request&,
                   const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
                   const std::string& primaryLogId) {
                constexpr const char* resourceNotFoundMsg =
                    "Resource Not Found";

                size_t indexCper = 0;
                bool isSingleCper = false;

                std::string filePath = CPER_LOG_DIR + primaryLogId;
                auto const pos = filePath.find_last_of('@');
                if (pos != std::string::npos)
                {
                    indexCper = static_cast<size_t>(
                        std::stoi(filePath.substr(pos + 1)));
                    filePath.erase(pos);
                    isSingleCper = true;
                }

                if (!std::filesystem::exists(filePath))
                {
                    BMCWEB_LOG_ERROR << "Not found CPER file:" << filePath;
                    asyncResp->res.result(
                        boost::beast::http::status::not_found);
                    asyncResp->res.jsonValue["Description"] =
                        resourceNotFoundMsg;
                    return;
                }

                std::string contentDispositionParam =
                    "attachment; filename=\"" + primaryLogId + "\"";
                asyncResp->res.addHeader("Content-Disposition",
                                         contentDispositionParam);

                if (isSingleCper)
                {

                    json_object* jsonCper =
                        getCperJsonObject(indexCper, filePath, isSingleCper);

                    if (jsonCper == NULL)
                    {
                        BMCWEB_LOG_ERROR
                            << primaryLogId << ":Invalid single CPER index: "
                            << indexCper;
                        asyncResp->res.result(
                            boost::beast::http::status::not_found);
                        asyncResp->res.jsonValue["Description"] =
                            primaryLogId + ":Invalid single CPER index " +
                            std::to_string(indexCper);
                        return;
                    }

                    filePath = "/tmp/cper-tmep-file";
                    // Convert to IR.
                    FILE* cperOutFile = fopen(filePath.c_str(), "w+");
                    ir_to_cper(jsonCper,cperOutFile);
                    fclose(cperOutFile);

                    json_object_put(jsonCper);
                }

                std::ifstream ifs(filePath, std::ios::in | std::ios::binary);
                std::string cperRawData(std::istreambuf_iterator<char>{ifs},
                                    {});
                asyncResp->res.body().assign(
                    static_cast<std::string>(cperRawData));

            });
}

inline void requestRoutesRasLogDownloadJson(App& app)
{
    // Note: Deviated from redfish privilege registry for GET & HEAD
    // method for security reasons.
    BMCWEB_ROUTE(
        app,
        "/redfish/v1/Systems/system/LogServices/RasEvent/Entries/<str>/json")
        .privileges(redfish::privileges::getLogEntry)
        .methods(boost::beast::http::verb::get)(
            [](const crow::Request&,
               const std::shared_ptr<bmcweb::AsyncResp>& asyncResp,
               const std::string& primaryLogId) {
                size_t indexCper = 0;
                bool isSingleCper = false;

                std::string filePath = CPER_LOG_DIR + primaryLogId;
                auto const pos = filePath.find_last_of('@');
                if (pos != std::string::npos)
                {
                    indexCper = std::stoul(filePath.substr(pos + 1));
                    filePath.erase(pos);
                    isSingleCper = true;
                }

                if (!std::filesystem::exists(filePath))
                {
                    messages::resourceMissingAtURI(
                        asyncResp->res, primaryLogId + "/" + filePath);
                    return;
                }

                json_object* jsonCper =
                    getCperJsonObject(indexCper, filePath, isSingleCper);

                std::string output = json_object_to_json_string_ext(
                    jsonCper, JSON_C_TO_STRING_PRETTY);

                json_object_put(jsonCper);

                asyncResp->res.body() = std::move(output);
            });
}

#endif
}
