# Author: RussianPanda
# Reference: https://n1ght-w0lf.github.io/tutorials/dotnet-string-decryptor/
# Tested on sample:
# 008f9352765d1b3360726363e3e179b527a566bc59acecea06bd16eb16b66c5d

import os
from pathlib import Path
from sys import argv
from tempfile import NamedTemporaryFile
from typing import BinaryIO, List, Optional

import clr
from maco.extractor import Extractor
from maco.model import ConnUsageEnum, ExtractorModel

# Check default location from package install
dn_lib_found = list(Path("/usr/lib").glob("**/dnlib.dll"))
DNLIB_PACKAGE_PATH = str(dn_lib_found[0]) if dn_lib_found else "dnlib"

DNLIB_PATH = os.environ.get("DNLIB_PATH", DNLIB_PACKAGE_PATH)
if not os.path.exists(DNLIB_PATH):
    raise FileNotFoundError(DNLIB_PATH)
clr.AddReference(DNLIB_PATH)

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


class MetaStealer(Extractor):
    family = "MetaStealer"
    author = "@RussianPanda"
    last_modified = "2024-02-02"
    sharing: str = "TLP:CLEAR"
    reference: str = "https://russianpanda.com/2023/11/20/MetaStealer-Redline%27s-Doppelganger/"
    yara_rule: str = """
import "pe"
rule MetaStealer_core_payload {

	meta:
		author = "RussianPanda"
		decription = "Detects MetaStealer Core Payload"
		date = "12/29/2023"

	strings:
		$s1 = "FileScannerRule"
		$s2 = "TreeObject"
		$s3 = "Schema"
		$s4 = "StringDecrypt"
		$s5 = "AccountDetails"

	condition:
		4 of ($s*)
		and pe.imports("mscoree.dll")
}
"""

    def run(self, stream: BinaryIO, matches: List = []) -> Optional[ExtractorModel]:
        with NamedTemporaryFile() as file:
            file.write(stream.read())
            file.flush()

            file_path = file.name
            module = load_net_module(file_path)
            assembly = load_net_assembly(file_path)
            suspected_methods = find_decryption_methods(assembly)
            results = invoke_methods(module, suspected_methods)

            C2 = None
            Build_ID = None

            for location, decrypted_string in results.items():
                self.logger.info(f"Decryption Location: {location}, Decrypted String: {decrypted_string}")

                if location == "Program.ReadLine":
                    C2 = decrypted_string
                elif location == "Schema13.TreeObject25":
                    Build_ID = decrypted_string

            cfg = None
            if C2 or Build_ID:
                cfg = ExtractorModel(family=self.family)
            else:
                # Nothing found
                return

            # Print the values of C2 and Build ID if they are found
            if C2:
                self.logger.info("-----------------------------------------------------------------------------------")
                self.logger.info(f"C2: {C2}")
                cfg.http.append(cfg.Http(uri=C2, usage=ConnUsageEnum.c2))
            if Build_ID:
                self.logger.info(f"Build ID: {Build_ID}")
                cfg.other["Build ID"] = Build_ID

            return cfg


if __name__ == "__main__":
    parser = MetaStealer()
    file_path = argv[1]

    with open(file_path, "rb") as f:
        result = parser.run(f)
        if result:
            print(result.model_dump_json(indent=2, exclude_none=True, exclude_defaults=True))
        else:
            print("No configuration extracted")
