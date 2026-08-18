using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dracula.ManagedHost
{
    public class JsonRpcRequest
    {
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("method")]
        public string Method { get; set; } = string.Empty;

        [JsonPropertyName("params")]
        public Dictionary<string, JsonElement>? Params { get; set; }
    }

    public class JsonRpcResponse
    {
        [JsonPropertyName("jsonrpc")]
        public string JsonRpc => "2.0";

        [JsonPropertyName("id")]
        public string? Id { get; set; }

        [JsonPropertyName("result")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object? Result { get; set; }

        [JsonPropertyName("error")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public object? Error { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // Bounded memory/resource configuration
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = new UTF8Encoding(false);

            if (args.Length > 0 && args[0] == "--test")
            {
                Console.WriteLine("Dracula.ManagedHost OK (.NET 10)");
                return;
            }

            string? line;
            while ((line = Console.ReadLine()) != null)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                JsonRpcResponse response = ProcessRequest(line);
                string jsonOutput = JsonSerializer.Serialize(response, new JsonSerializerOptions
                {
                    WriteIndented = false,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
                });

                Console.WriteLine(jsonOutput);
                Console.Out.Flush();
            }
        }

        static JsonRpcResponse ProcessRequest(string rawJson)
        {
            string? reqId = "1";
            try
            {
                using var doc = JsonDocument.Parse(rawJson);
                var root = doc.RootElement;
                if (root.TryGetProperty("id", out var idElem))
                {
                    reqId = idElem.ToString();
                }

                if (!root.TryGetProperty("method", out var methodElem))
                {
                    return new JsonRpcResponse
                    {
                        Id = reqId,
                        Error = new { code = -32600, message = "Missing 'method' field in request" }
                    };
                }

                string method = methodElem.GetString() ?? string.Empty;
                var paramsDict = new Dictionary<string, JsonElement>();
                if (root.TryGetProperty("params", out var pElem) && pElem.ValueKind == JsonValueKind.Object)
                {
                    foreach (var prop in pElem.EnumerateObject())
                    {
                        paramsDict[prop.Name] = prop.Value.Clone();
                    }
                }

                return HandleMethod(method, reqId, paramsDict);
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse
                {
                    Id = reqId,
                    Error = new { code = -32603, message = $"Internal ManagedHost error: {ex.Message}" }
                };
            }
        }

        static JsonRpcResponse HandleMethod(string method, string? reqId, Dictionary<string, JsonElement> p)
        {
            switch (method.ToLowerInvariant())
            {
                case "ping":
                    return new JsonRpcResponse
                    {
                        Id = reqId,
                        Result = new
                        {
                            status = "pong",
                            runtime = Environment.Version.ToString(),
                            framework = ".NET 10.0",
                            pid = Environment.ProcessId
                        }
                    };

                case "inspect_assembly":
                {
                    if (!p.TryGetValue("path", out var pathElem))
                        return ParamError(reqId, "path");

                    string path = pathElem.GetString() ?? string.Empty;
                    return InspectAssembly(reqId, path);
                }

                case "list_types":
                {
                    if (!p.TryGetValue("path", out var pathElem))
                        return ParamError(reqId, "path");

                    string path = pathElem.GetString() ?? string.Empty;
                    return ListTypes(reqId, path);
                }

                case "inspect_method":
                {
                    if (!p.TryGetValue("path", out var pathElem))
                        return ParamError(reqId, "path");
                    if (!p.TryGetValue("type", out var typeElem))
                        return ParamError(reqId, "type");
                    if (!p.TryGetValue("method", out var methodElem))
                        return ParamError(reqId, "method");

                    string path = pathElem.GetString() ?? string.Empty;
                    string typeName = typeElem.GetString() ?? string.Empty;
                    string methodName = methodElem.GetString() ?? string.Empty;
                    return InspectMethod(reqId, path, typeName, methodName);
                }

                case "list_strings":
                {
                    if (!p.TryGetValue("path", out var pathElem))
                        return ParamError(reqId, "path");

                    string path = pathElem.GetString() ?? string.Empty;
                    return ListUserStrings(reqId, path);
                }

                case "list_pinvokes":
                {
                    if (!p.TryGetValue("path", out var pathElem))
                        return ParamError(reqId, "path");

                    string path = pathElem.GetString() ?? string.Empty;
                    return ListPInvokes(reqId, path);
                }

                default:
                    return new JsonRpcResponse
                    {
                        Id = reqId,
                        Error = new { code = -32601, message = $"Unknown method: '{method}'" }
                    };
            }
        }

        static JsonRpcResponse ParamError(string? reqId, string paramName)
        {
            return new JsonRpcResponse
            {
                Id = reqId,
                Error = new { code = -32602, message = $"Missing required param: '{paramName}'" }
            };
        }

        static JsonRpcResponse InspectAssembly(string? reqId, string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new JsonRpcResponse
                {
                    Id = reqId,
                    Error = new { code = -32001, message = $"File not found: {filePath}" }
                };
            }

            try
            {
                using var stream = File.OpenRead(filePath);
                using var peReader = new PEReader(stream);
                if (!peReader.HasMetadata)
                {
                    return new JsonRpcResponse
                    {
                        Id = reqId,
                        Error = new { code = -32002, message = "Target PE does not contain CLR metadata." }
                    };
                }

                var mr = peReader.GetMetadataReader();
                var asmDef = mr.IsAssembly ? mr.GetAssemblyDefinition() : default;

                string asmName = mr.IsAssembly ? mr.GetString(asmDef.Name) : Path.GetFileNameWithoutExtension(filePath);
                string version = mr.IsAssembly ? asmDef.Version.ToString() : "0.0.0.0";
                string culture = mr.IsAssembly && !asmDef.Culture.IsNil ? mr.GetString(asmDef.Culture) : "neutral";

                var moduleDef = mr.GetModuleDefinition();
                string moduleName = mr.GetString(moduleDef.Name);

                int typeCount = mr.TypeDefinitions.Count;
                int methodCount = mr.MethodDefinitions.Count;

                string entryPoint = "None";
                var peHeaders = peReader.PEHeaders;
                if (peHeaders.CorHeader != null && peHeaders.CorHeader.EntryPointTokenOrRelativeVirtualAddress != 0)
                {
                    int token = peHeaders.CorHeader.EntryPointTokenOrRelativeVirtualAddress;
                    entryPoint = $"0x{token:X8}";
                }

                return new JsonRpcResponse
                {
                    Id = reqId,
                    Result = new
                    {
                        path = filePath,
                        assembly_name = asmName,
                        version = version,
                        culture = culture,
                        module_name = moduleName,
                        type_count = typeCount,
                        method_count = methodCount,
                        entry_point = entryPoint,
                        is_assembly = mr.IsAssembly
                    }
                };
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse
                {
                    Id = reqId,
                    Error = new { code = -32003, message = $"Failed to parse assembly metadata: {ex.Message}" }
                };
            }
        }

        static JsonRpcResponse ListTypes(string? reqId, string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32001, message = $"File not found: {filePath}" } };
            }

            try
            {
                using var stream = File.OpenRead(filePath);
                using var peReader = new PEReader(stream);
                if (!peReader.HasMetadata)
                {
                    return new JsonRpcResponse { Id = reqId, Error = new { code = -32002, message = "Target PE lacks CLR metadata." } };
                }

                var mr = peReader.GetMetadataReader();
                var typesList = new List<object>();

                foreach (var handle in mr.TypeDefinitions)
                {
                    var typeDef = mr.GetTypeDefinition(handle);
                    string ns = mr.GetString(typeDef.Namespace);
                    string name = mr.GetString(typeDef.Name);
                    string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

                    string baseType = "None";
                    if (!typeDef.BaseType.IsNil)
                    {
                        if (typeDef.BaseType.Kind == HandleKind.TypeReference)
                        {
                            var tr = mr.GetTypeReference((TypeReferenceHandle)typeDef.BaseType);
                            string trNs = mr.GetString(tr.Namespace);
                            string trName = mr.GetString(tr.Name);
                            baseType = string.IsNullOrEmpty(trNs) ? trName : $"{trNs}.{trName}";
                        }
                        else if (typeDef.BaseType.Kind == HandleKind.TypeDefinition)
                        {
                            var td = mr.GetTypeDefinition((TypeDefinitionHandle)typeDef.BaseType);
                            string tdNs = mr.GetString(td.Namespace);
                            string tdName = mr.GetString(td.Name);
                            baseType = string.IsNullOrEmpty(tdNs) ? tdName : $"{tdNs}.{tdName}";
                        }
                    }

                    int methodCount = 0;
                    foreach (var _ in typeDef.GetMethods()) methodCount++;

                    int fieldCount = 0;
                    foreach (var _ in typeDef.GetFields()) fieldCount++;

                    typesList.Add(new
                    {
                        full_name = fullName,
                        namespace_name = ns,
                        name = name,
                        base_type = baseType,
                        attributes = typeDef.Attributes.ToString(),
                        is_interface = (typeDef.Attributes & TypeAttributes.Interface) != 0,
                        is_class = (typeDef.Attributes & TypeAttributes.Class) != 0 && (typeDef.Attributes & TypeAttributes.Interface) == 0,
                        method_count = methodCount,
                        field_count = fieldCount
                    });
                }

                return new JsonRpcResponse
                {
                    Id = reqId,
                    Result = new
                    {
                        total_types = typesList.Count,
                        types = typesList
                    }
                };
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32003, message = $"Failed to list types: {ex.Message}" } };
            }
        }

        static JsonRpcResponse InspectMethod(string? reqId, string filePath, string targetType, string targetMethod)
        {
            if (!File.Exists(filePath))
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32001, message = $"File not found: {filePath}" } };
            }

            try
            {
                using var stream = File.OpenRead(filePath);
                using var peReader = new PEReader(stream);
                if (!peReader.HasMetadata)
                {
                    return new JsonRpcResponse { Id = reqId, Error = new { code = -32002, message = "Target PE lacks CLR metadata." } };
                }

                var mr = peReader.GetMetadataReader();
                foreach (var typeHandle in mr.TypeDefinitions)
                {
                    var typeDef = mr.GetTypeDefinition(typeHandle);
                    string ns = mr.GetString(typeDef.Namespace);
                    string name = mr.GetString(typeDef.Name);
                    string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

                    if (!fullName.Equals(targetType, StringComparison.OrdinalIgnoreCase) &&
                        !name.Equals(targetType, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    foreach (var methodHandle in typeDef.GetMethods())
                    {
                        var methodDef = mr.GetMethodDefinition(methodHandle);
                        string methodName = mr.GetString(methodDef.Name);

                        if (!methodName.Equals(targetMethod, StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        bool isPInvoke = (methodDef.Attributes & MethodAttributes.PinvokeImpl) != 0;
                        string pinvokeDll = "";
                        string pinvokeEntry = "";
                        if (isPInvoke)
                        {
                            var import = methodDef.GetImport();
                            pinvokeEntry = mr.GetString(import.Name);
                            var modRef = mr.GetModuleReference(import.Module);
                            pinvokeDll = mr.GetString(modRef.Name);
                        }

                        int rva = methodDef.RelativeVirtualAddress;
                        int ilSize = 0;
                        string ilHex = "";
                        List<string> disasm = new List<string>();

                        if (rva != 0)
                        {
                            try
                            {
                                var methodBody = peReader.GetMethodBody(rva);
                                byte[] ilBytes = methodBody.GetILBytes() ?? Array.Empty<byte>();
                                ilSize = ilBytes.Length;
                                ilHex = Convert.ToHexString(ilBytes);

                                // Lightweight IL decoder
                                for (int i = 0; i < Math.Min(ilBytes.Length, 128); ++i)
                                {
                                    disasm.Add($"IL_{i:X4}: 0x{ilBytes[i]:X2}");
                                }
                            }
                            catch (Exception bodyEx)
                            {
                                disasm.Add($"; Could not decode method body: {bodyEx.Message}");
                            }
                        }

                        return new JsonRpcResponse
                        {
                            Id = reqId,
                            Result = new
                            {
                                type = fullName,
                                method = methodName,
                                rva = $"0x{rva:X8}",
                                attributes = methodDef.Attributes.ToString(),
                                is_static = (methodDef.Attributes & MethodAttributes.Static) != 0,
                                is_pinvoke = isPInvoke,
                                pinvoke_dll = pinvokeDll,
                                pinvoke_entrypoint = pinvokeEntry,
                                il_size = ilSize,
                                il_hex = ilHex,
                                il_disasm = disasm
                            }
                        };
                    }
                }

                return new JsonRpcResponse
                {
                    Id = reqId,
                    Error = new { code = -32004, message = $"Method '{targetMethod}' in type '{targetType}' not found." }
                };
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32003, message = $"Failed to inspect method: {ex.Message}" } };
            }
        }

        static JsonRpcResponse ListUserStrings(string? reqId, string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32001, message = $"File not found: {filePath}" } };
            }

            try
            {
                using var stream = File.OpenRead(filePath);
                using var peReader = new PEReader(stream);
                if (!peReader.HasMetadata)
                {
                    return new JsonRpcResponse { Id = reqId, Error = new { code = -32002, message = "Target lacks CLR metadata." } };
                }

                var mr = peReader.GetMetadataReader();
                var userStrings = new List<string>();

                var handle = System.Reflection.Metadata.Ecma335.MetadataTokens.UserStringHandle(1);
                int limit = 2000;
                while (!handle.IsNil && userStrings.Count < limit)
                {
                    try
                    {
                        string str = mr.GetUserString(handle);
                        if (!string.IsNullOrEmpty(str))
                        {
                            userStrings.Add(str);
                        }
                        handle = mr.GetNextHandle(handle);
                    }
                    catch
                    {
                        break;
                    }
                }

                return new JsonRpcResponse
                {
                    Id = reqId,
                    Result = new
                    {
                        count = userStrings.Count,
                        strings = userStrings
                    }
                };
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32003, message = $"Failed to list strings: {ex.Message}" } };
            }
        }

        static JsonRpcResponse ListPInvokes(string? reqId, string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32001, message = $"File not found: {filePath}" } };
            }

            try
            {
                using var stream = File.OpenRead(filePath);
                using var peReader = new PEReader(stream);
                if (!peReader.HasMetadata)
                {
                    return new JsonRpcResponse { Id = reqId, Error = new { code = -32002, message = "Target lacks CLR metadata." } };
                }

                var mr = peReader.GetMetadataReader();
                var pinvokes = new List<object>();

                foreach (var methodHandle in mr.MethodDefinitions)
                {
                    var methodDef = mr.GetMethodDefinition(methodHandle);
                    if ((methodDef.Attributes & MethodAttributes.PinvokeImpl) == 0) continue;

                    var typeDef = mr.GetTypeDefinition(methodDef.GetDeclaringType());
                    string ns = mr.GetString(typeDef.Namespace);
                    string typeName = mr.GetString(typeDef.Name);
                    string fullTypeName = string.IsNullOrEmpty(ns) ? typeName : $"{ns}.{typeName}";
                    string methodName = mr.GetString(methodDef.Name);

                    var import = methodDef.GetImport();
                    string entryName = mr.GetString(import.Name);
                    var modRef = mr.GetModuleReference(import.Module);
                    string dllName = mr.GetString(modRef.Name);

                    pinvokes.Add(new
                    {
                        type = fullTypeName,
                        method = methodName,
                        dll = dllName,
                        entry_point = entryName,
                        calling_convention = import.Attributes.ToString()
                    });
                }

                return new JsonRpcResponse
                {
                    Id = reqId,
                    Result = new
                    {
                        count = pinvokes.Count,
                        pinvokes = pinvokes
                    }
                };
            }
            catch (Exception ex)
            {
                return new JsonRpcResponse { Id = reqId, Error = new { code = -32003, message = $"Failed to list P/Invokes: {ex.Message}" } };
            }
        }
    }
}
