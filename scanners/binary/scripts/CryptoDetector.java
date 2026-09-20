// Ghidra script to detect cryptographic constants and API calls in binaries
// @category Crypto
// @author Trinetra

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.io.*;
import java.util.*;

public class CryptoDetector extends GhidraScript {
    
    // Known crypto constants
    private static final byte[] AES_SBOX = {
        (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
        (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76
    };
    
    private static final int[] SHA256_IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    private static final int[] MD5_MAGIC = {
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    };
    
    private List<Finding> findings = new ArrayList<>();
    
    public void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        
        println("Trinetra Crypto Detector - Starting analysis");
        
        // Search for crypto constants
        findAESSbox();
        findSHA256Constants();
        findMD5Constants();
        findDESConstants();
        
        // Search for crypto API calls
        findCryptoAPICalls();
        
        // Search for linked crypto libraries
        findCryptoLibraries();
        
        // Write findings to JSON
        writeFindings(outputFile);
        
        println("Analysis complete. Found " + findings.size() + " crypto artifacts.");
    }
    
    private void findAESSbox() throws Exception {
        println("Searching for AES S-box...");
        Memory mem = currentProgram.getMemory();
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) {
                continue;
            }
            
            byte[] bytes = new byte[256];
            Address addr = block.getStart();
            
            while (addr.compareTo(block.getEnd()) < 0) {
                try {
                    mem.getBytes(addr, bytes);
                    
                    // Check if this looks like an AES S-box
                    if (isAESSbox(bytes)) {
                        findings.add(new Finding(
                            "constant",
                            "AES",
                            addr.toString(),
                            bytesToHex(bytes, 16),
                            256,
                            "AES S-box table detected"
                        ));
                        println("  Found AES S-box at " + addr);
                        addr = addr.add(256);
                        continue;
                    }
                } catch (Exception e) {
                    // Continue scanning
                }
                addr = addr.add(1);
            }
        }
    }
    
    private boolean isAESSbox(byte[] bytes) {
        if (bytes.length < 256) return false;
        
        // Check first few bytes match known S-box
        for (int i = 0; i < Math.min(16, AES_SBOX.length); i++) {
            if (bytes[i] != AES_SBOX[i]) {
                return false;
            }
        }
        
        // Verify all values 0-255 appear exactly once (permutation property)
        boolean[] seen = new boolean[256];
        for (int i = 0; i < 256; i++) {
            int val = bytes[i] & 0xFF;
            if (seen[val]) return false;
            seen[val] = true;
        }
        
        return true;
    }
    
    private void findSHA256Constants() throws Exception {
        println("Searching for SHA-256 IV...");
        Memory mem = currentProgram.getMemory();
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) {
                continue;
            }
            
            Address addr = block.getStart();
            
            while (addr.compareTo(block.getEnd().subtract(31)) < 0) {
                try {
                    boolean match = true;
                    for (int i = 0; i < SHA256_IV.length; i++) {
                        int value = mem.getInt(addr.add(i * 4));
                        if (value != SHA256_IV[i]) {
                            match = false;
                            break;
                        }
                    }
                    
                    if (match) {
                        findings.add(new Finding(
                            "constant",
                            "SHA256",
                            addr.toString(),
                            "SHA-256 initialization vector",
                            256,
                            "SHA-256 IV constants detected"
                        ));
                        println("  Found SHA-256 IV at " + addr);
                        addr = addr.add(32);
                        continue;
                    }
                } catch (Exception e) {
                    // Continue scanning
                }
                addr = addr.add(4);
            }
        }
    }
    
    private void findMD5Constants() throws Exception {
        println("Searching for MD5 magic constants...");
        Memory mem = currentProgram.getMemory();
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) {
                continue;
            }
            
            Address addr = block.getStart();
            
            while (addr.compareTo(block.getEnd().subtract(15)) < 0) {
                try {
                    boolean match = true;
                    for (int i = 0; i < MD5_MAGIC.length; i++) {
                        int value = mem.getInt(addr.add(i * 4));
                        if (value != MD5_MAGIC[i]) {
                            match = false;
                            break;
                        }
                    }
                    
                    if (match) {
                        findings.add(new Finding(
                            "constant",
                            "MD5",
                            addr.toString(),
                            "MD5 magic constants",
                            128,
                            "MD5 initialization constants detected"
                        ));
                        println("  Found MD5 constants at " + addr);
                        addr = addr.add(16);
                        continue;
                    }
                } catch (Exception e) {
                    // Continue scanning
                }
                addr = addr.add(4);
            }
        }
    }
    
    private void findDESConstants() throws Exception {
        println("Searching for DES S-boxes...");
        // DES has 8 S-boxes, each 4x16 = 64 entries
        // This is a simplified detection; full DES detection would check all 8 boxes
        Memory mem = currentProgram.getMemory();
        
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isLoaded()) {
                continue;
            }
            
            // Look for characteristic DES patterns (simplified)
            // In production, you'd check for the actual S-box values
            Address addr = block.getStart();
            
            while (addr.compareTo(block.getEnd().subtract(512)) < 0) {
                try {
                    // DES S-boxes have specific properties we can check
                    byte[] bytes = new byte[64];
                    mem.getBytes(addr, bytes);
                    
                    if (looksDESish(bytes)) {
                        findings.add(new Finding(
                            "constant",
                            "DES",
                            addr.toString(),
                            "DES S-box",
                            56,
                            "Possible DES S-box structure detected"
                        ));
                        println("  Found possible DES S-box at " + addr);
                        addr = addr.add(64);
                        continue;
                    }
                } catch (Exception e) {
                    // Continue scanning
                }
                addr = addr.add(1);
            }
        }
    }
    
    private boolean looksDESish(byte[] bytes) {
        // Simplified heuristic: DES S-box values are all < 16
        int validCount = 0;
        for (byte b : bytes) {
            if ((b & 0xFF) < 16) {
                validCount++;
            }
        }
        return validCount > 56; // Most values should be < 16
    }
    
    private void findCryptoAPICalls() throws Exception {
        println("Searching for crypto API calls...");
        
        String[] cryptoAPIs = {
            "AES_", "RSA_", "SHA256", "SHA512", "MD5", "HMAC",
            "EVP_", "CRYPTO_", "BN_", "EC_KEY", "ECDSA",
            "mbedtls_", "CryptGenRandom", "BCrypt",
            "ChaCha20", "Poly1305", "Ed25519"
        };
        
        SymbolTable symTable = currentProgram.getSymbolTable();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        
        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                String name = sym.getName();
                
                for (String api : cryptoAPIs) {
                    if (name.contains(api)) {
                        String algo = extractAlgorithm(name);
                        findings.add(new Finding(
                            "api_call",
                            algo,
                            sym.getAddress().toString(),
                            name,
                            0,
                            "Crypto API function: " + name
                        ));
                        println("  Found crypto API: " + name);
                        break;
                    }
                }
            }
        }
        
        // Also search for string references to crypto functions
        for (Data data : currentProgram.getListing().getDefinedData(true)) {
            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();
                for (String api : cryptoAPIs) {
                    if (str.contains(api)) {
                        findings.add(new Finding(
                            "api_call",
                            extractAlgorithm(str),
                            data.getAddress().toString(),
                            str,
                            0,
                            "Crypto API string reference: " + str
                        ));
                        break;
                    }
                }
            }
        }
    }
    
    private void findCryptoLibraries() throws Exception {
        println("Searching for linked crypto libraries...");
        
        String[] cryptoLibs = {
            "libcrypto", "libssl", "openssl", "mbedtls", "botan",
            "libsodium", "bcrypt", "cng", "cryptopp"
        };
        
        ExternalManager extMgr = currentProgram.getExternalManager();
        
        for (String libName : extMgr.getExternalLibraryNames()) {
            String lower = libName.toLowerCase();
            for (String cryptoLib : cryptoLibs) {
                if (lower.contains(cryptoLib)) {
                    findings.add(new Finding(
                        "library",
                        "",  // Libraries don't specify algorithm
                        "EXTERNAL",
                        libName,
                        0,
                        "Linked crypto library: " + libName
                    ));
                    println("  Found crypto library: " + libName);
                    break;
                }
            }
        }
    }
    
    private String extractAlgorithm(String name) {
        String upper = name.toUpperCase();
        if (upper.contains("AES")) return "AES";
        if (upper.contains("RSA")) return "RSA";
        if (upper.contains("SHA256")) return "SHA256";
        if (upper.contains("SHA512")) return "SHA512";
        if (upper.contains("SHA1")) return "SHA1";
        if (upper.contains("MD5")) return "MD5";
        if (upper.contains("ECDSA")) return "ECDSA";
        if (upper.contains("CHACHA")) return "ChaCha20";
        if (upper.contains("ED25519")) return "Ed25519";
        if (upper.contains("HMAC")) return "HMAC";
        return "CRYPTO";
    }
    
    private String bytesToHex(byte[] bytes, int limit) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, limit); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > limit) {
            sb.append("...");
        }
        return sb.toString();
    }
    
    private void writeFindings(String outputFile) throws Exception {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(findings);
        
        try (FileWriter writer = new FileWriter(outputFile)) {
            writer.write(json);
        }
    }
    
    class Finding {
        String type;
        String algorithm;
        String address;
        String value;
        int key_size;
        String note;
        
        Finding(String type, String algorithm, String address, String value, int key_size, String note) {
            this.type = type;
            this.algorithm = algorithm;
            this.address = address;
            this.value = value;
            this.key_size = key_size;
            this.note = note;
        }
    }
}
