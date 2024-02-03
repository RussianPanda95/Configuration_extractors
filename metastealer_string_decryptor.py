# Author: RussianPanda
# Reference: https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor/
# Tested on sample:
# 008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d

import os
import sys

import clr

# Add reference to dnlib.dll
dnlib_path = "dnlib.dll"
if not os.path.exists(dnlib_path):
    raise FileNotFoundError(dnlib_path)
clr.AddReference(dnlib_path)
import dnlib
from dnlib.DotNet import ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from System import Convert, Int32, String
from System.Reflection import Assembly, BindingFlags

decryption_signature = [{"Parameters": ["System.Int32"], "ReturnType": "System.String"}]


def load_net_module(file_path):
    return ModuleDefMD.Load(file_path)


def load_net_assembly(file_path):
    return Assembly.LoadFile(file_path)


def find_decryption_methods(assembly):
    suspected_methods = []
    flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic
    for module_type in assembly.GetTypes():
        for method in module_type.GetMethods(flags):
            for sig in decryption_signature:
                if method_matches_signature(method, sig):
                    suspected_methods.append(method)
    return suspected_methods


def method_matches_signature(method, signature):
    parameters = method.GetParameters()
    return (
        len(parameters) == len(signature["Parameters"])
        and method.ReturnType.FullName == signature["ReturnType"]
        and all(parameters[i].ParameterType.FullName == signature["Parameters"][i] for i in range(len(parameters)))
    )


def get_operand_value(insn, param_type):
    if "Int32" in param_type and insn.IsLdcI4():
        return Int32(insn.GetLdcI4Value())
    elif "String" in param_type and insn.OpCode == OpCodes.Ldstr:
        return insn.Operand
    return None


def invoke_methods(module, suspected_methods):
    results = {}
    for method in suspected_methods:
        for module_type in module.Types:
            if not module_type.HasMethods:
                continue
            for m in module_type.Methods:
                if m.HasBody:
                    for insnIdx, insn in enumerate(m.Body.Instructions):
                        if insn.OpCode == OpCodes.Call:
                            called_method_name = str(insn.Operand)
                            if method.Name in called_method_name:
                                params = extract_parameters(m.Body.Instructions, insnIdx, method)
                                if len(params) == len(method.GetParameters()):
                                    try:
                                        result = invoke_method_safely(method, params)
                                        if result is not None:
                                            location = f"{module_type.FullName}.{m.Name}"
                                            results[location] = result
                                    except Exception as e:
                                        None
    return results


def invoke_method_safely(method, params):
    try:
        if method.Name == "Get" and isinstance(params[0], int):
            # Adjust the range as necessary
            if 0 <= params[0] < 100:
                return method.Invoke(None, params)
        else:
            return method.Invoke(None, params)
    except System.ArgumentOutOfRangeException:
        # Silently handle ArgumentOutOfRangeException for method Get
        if method.Name == "Get":
            return None
    except Exception as e:
        print(f"Error invoking method {method.Name}: {e}")
        return None


def extract_parameters(instructions, insn_idx, method):
    params = []
    num_params = len(method.GetParameters())
    if insn_idx < num_params:
        return []

    for i, param_type in enumerate(method.GetParameters()):
        operand = get_operand_value(instructions[insn_idx - 1], str(param_type.ParameterType))
        if operand is not None:
            params.append(operand)
    return list(reversed(params))


def invoke_and_process(method, params):
    try:
        result = method.Invoke(None, params)
        if method.ReturnType.FullName == "System.Object" and result is not None:
            return Convert.ToString(result)
        return result
    except Exception as e:
        print(f"Error invoking method {method.Name}: {e}")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: metastealer_string_decryptor.py <payload>")

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        sys.exit("File not found")

    if not os.path.isabs(file_path):
        file_path = os.path.abspath(file_path)

    module = load_net_module(file_path)
    assembly = load_net_assembly(file_path)
    suspected_methods = find_decryption_methods(assembly)
    results = invoke_methods(module, suspected_methods)

    C2 = None
    Build_ID = None

    for location, decrypted_string in results.items():
        print(f"Decryption Location: {location}, Decrypted String: {decrypted_string}")

        if location == "Program.ReadLine":
            C2 = decrypted_string
        elif location == "Schema13.TreeObject25":
            Build_ID = decrypted_string

    # Print the values of C2 and Build ID if they are found
    if C2:
        print("-----------------------------------------------------------------------------------")
        print(f"C2: {C2}")
    if Build_ID:
        print(f"Build ID: {Build_ID}")
