/***
 * CERT Kaiju
 * Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
 * INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own license:
 * 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle.
 * 2. Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021 National Security Administration.
 * 3. GSON (https://github.com/google/gson/blob/master/LICENSE) Copyright 2020 Google.
 * 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md) Copyright 2020 JUnit Team.
 *
 * DM21-0087
 */
package kaiju.hashing;

import ghidra.util.ObjectStorage;
import ghidra.util.Saveable;

import java.lang.Byte;
import java.util.ArrayList;
import java.util.Vector;

/**
 * A Saveable object representing FnHash analysis work, including various
 * computed hashes for functions.
 * This object implements the Saveable interface and so can be stored into the
 * Ghidra Project database when the user hits the "save" button.
 * See: https://ghidra.re/ghidra_docs/api/ghidra/util/Saveable.html
 */
public class FnHashSaveable implements Saveable {

    // store each hash individually in this object
    private String file_md5;
    private String fn_addr;
    private Integer num_basic_blocks;
    private Integer num_basic_blocks_in_cfg;
    private Integer num_instructions;
    private Integer num_bytes;
    private String mnemonic_count_string;
    private String mnemonic_category_count_string;
    private byte[] exact_bytes;
    private String exact_hash;
    private byte[] pic_bytes;
    private String pic_hash;
    private String composite_pic_hash;
    private String mnemonic_hash;
    private String mnemonic_count_hash;
    private String mnemonic_category_hash;
    private String mnemonic_category_count_hash;
    
    // let the ghidra database know what it's storing
    // by making a schema of field types
    
    // WARNING: Think very hard before you change this schema! If you
    // absolutely must, then be sure to update the getSchemaVersion()
    // result to increment the schema version, and ideally add to
    // the upgrade() function to automatically adjust old saved data.
    // Also be sure to update getHashes() function below if needed.
    private Class<?>[] schema = new Class<?>[] {
        String.class, // file md5 containing this function
        String.class, // address this function starts at
        Integer.class, // number of basic blocks
        Integer.class, // number of basic blocks in the CFG
        Integer.class, // number of instructions in function
        Integer.class, // number of bytes in the function
        String.class, // mnemonic count string (e.g., add:4;mv:12;jmp:3;...)
        String.class, // mnemonic category count string (e.g., MATH:2;LOGIC:5;...)
        // begin function hashes and bytes
        byte[].class, // exact bytes
        String.class, // exact hash
        byte[].class, // pic bytes
        String.class, // pic hash
        String.class, // composite pic hash
        String.class, // mnemonic hash
        String.class, // mnemonic count hash
        String.class, // mnemonic category hash
        String.class // mnemonic category count hash
    };
    
    // constructors
    public FnHashSaveable(String file_md5, String fn_addr, Integer num_basic_blocks, Integer num_basic_blocks_in_cfg, Integer num_instructions, Integer num_bytes, String mnemonic_count_string, String mnemonic_category_count_string, byte[] exact_bytes, String exact_hash, byte[] pic_bytes, String pic_hash, String composite_pic_hash, String mnemonic_hash, String mnemonic_count_hash, String mnemonic_category_hash, String mnemonic_category_count_hash) {
        this.file_md5 = file_md5;
        this.fn_addr = fn_addr;
        this.num_basic_blocks = num_basic_blocks;
        this.num_basic_blocks_in_cfg = num_basic_blocks_in_cfg;
        this.num_instructions = num_instructions;
        this.num_bytes = num_bytes;
        this.mnemonic_count_string = mnemonic_count_string;
        this.mnemonic_category_count_string = mnemonic_category_count_string;
        this.exact_bytes = exact_bytes;
        this.exact_hash = exact_hash;
        this.pic_bytes = pic_bytes;
        this.pic_hash = pic_hash;
        this.composite_pic_hash= composite_pic_hash;
        this.mnemonic_hash = mnemonic_hash;
        this.mnemonic_count_hash = mnemonic_count_hash;
        this.mnemonic_category_hash = mnemonic_category_hash;
        this.mnemonic_category_count_hash = mnemonic_category_count_hash;
    }
    public FnHashSaveable() {
    }
    
    // WARNING: this function is tied to the schema above; if the schema
    // is changed, then this function most likely must be changed too!
    public Vector getHashes() {
        Vector hashes = new Vector();
        hashes.add(exact_hash);
        hashes.add(pic_hash);
        hashes.add(composite_pic_hash);
        hashes.add(mnemonic_hash);
        hashes.add(mnemonic_count_hash);
        hashes.add(mnemonic_category_hash);
        hashes.add(mnemonic_category_count_hash);
        return hashes;
    }
    
    public Integer getNumBasicBlocks() {
        return num_basic_blocks;
    }
    
    public Integer getNumBasicBlocksInCfg() {
        return num_basic_blocks_in_cfg;
    }
    
    public Integer getNumInstructions() {
        return num_instructions;
    }
    
    public Integer getNumBytes() {
        return num_bytes;
    }
    
    public String getMnemonicCountString() {
        return mnemonic_count_string;
    }
    
    public String getMnemonicCategoryCountString() {
        return mnemonic_category_count_string;
    }
    
    public byte[] getExactBytes() {
        return exact_bytes;
    }
    
    public String getExactHash() {
        return exact_hash;
    }
    
    public byte[] getPICBytes() {
        return pic_bytes;
    }
    
    public String getPICHash() {
        return pic_hash;
    }
    
    public String getCompositePICHash() {
        return composite_pic_hash;
    }
    
    public String getMnemonicCountHash() {
        return mnemonic_count_hash;
    }
    
    public String getMnemonicCategoryHash() {
        return mnemonic_category_hash;
    }
    
    public String getMnemonicCategoryCountHash() {
        return mnemonic_category_count_hash;
    }
    
    public String getMnemonicHash() {
        return mnemonic_hash;
    }
    
    /**
     * Ghidra uses this to get the schema so it can save and load
     * data from its project files.
     * @see ghidra.util.Saveable#getObjectStorageFields()
     */
    public Class<?>[] getObjectStorageFields() {
        return schema;
    }

    /**
     * @see ghidra.util.Saveable#save(ObjectStorage)
     */
    public void save(ObjectStorage objStorage) {
        objStorage.putString(file_md5);
        objStorage.putString(fn_addr);
        objStorage.putInt(num_basic_blocks);
        objStorage.putInt(num_basic_blocks_in_cfg);
        objStorage.putInt(num_instructions);
        objStorage.putInt(num_bytes);
        objStorage.putString(mnemonic_count_string);
        objStorage.putString(mnemonic_category_count_string);
        objStorage.putBytes(exact_bytes);
        objStorage.putString(exact_hash);
        objStorage.putBytes(pic_bytes);
        objStorage.putString(pic_hash);
        objStorage.putString(composite_pic_hash);
        objStorage.putString(mnemonic_hash);
        objStorage.putString(mnemonic_count_hash);
        objStorage.putString(mnemonic_category_hash);
        objStorage.putString(mnemonic_category_count_hash);
    }
    
    /**
     * @see ghidra.util.Saveable#restore(ObjectStorage)
     */
    public void restore(ObjectStorage objStorage) {
        file_md5 = objStorage.getString();
        fn_addr = objStorage.getString();
        num_basic_blocks = objStorage.getInt();
        num_basic_blocks_in_cfg = objStorage.getInt();
        num_instructions = objStorage.getInt();
        num_bytes = objStorage.getInt();
        mnemonic_count_string = objStorage.getString();
        mnemonic_category_count_string = objStorage.getString();
        exact_bytes = objStorage.getBytes();
        exact_hash = objStorage.getString();
        pic_bytes = objStorage.getBytes();
        pic_hash = objStorage.getString();
        composite_pic_hash = objStorage.getString();
        mnemonic_hash = objStorage.getString();
        mnemonic_count_hash = objStorage.getString();
        mnemonic_category_hash = objStorage.getString();
        mnemonic_category_count_hash = objStorage.getString();
    }
    
    /**
     * This is not a private Saveable; it is allowed to broadcast changes to
     * the rest of Ghidra's components. So we return false for not private.
     * @see ghidra.util.Saveable#isPrivate()
     */
    public boolean isPrivate() {
        return false;
    }
    
    /**
     * Sets the version of this schema. Should the schema change,
     * please increment the integer version.
     * @see ghidra.util.Saveable#getSchemaVersion()
     */
    public int getSchemaVersion() {
        return 0;
    }

    /**
     * If the schema changes, are we able to upgrade from the old schema
     * to the new one automatically? For now, the answer is No.
     * (Mostly because we are still using the first schema version.)
     * @see ghidra.util.Saveable#isUpgradeable(int)
     */
    public boolean isUpgradeable(int oldSchemaVersion) {
        return false;
    }

    /**
     * When more than one scehma version exists, this function can handle automated upgrades.
     * For now we just return false since there is no upgrade process that can succeed.
     * @see ghidra.util.Saveable#upgrade(ghidra.util.ObjectStorage, int, ghidra.util.ObjectStorage)
     */
    public boolean upgrade(ObjectStorage oldObjStorage, int oldSchemaVersion, ObjectStorage currentObjStorage) {
        return false;
    }
}
