#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <unordered_map>
#include <openssl/sha.h>
#include <thread>

using namespace std;

// Utility function to compute SHA-256 hash of a string
string sha256(const string& input) {
    unsigned char hashResult[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hashResult);
    
    stringstream ss;
    ss << hex << setw(2) << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << setw(2) << static_cast<int>(hashResult[i]);
    }
    return ss.str();
}

// Class representing a Block in the Blockchain
class Block {
public:
    string parentHash;      // Hash of the previous block
    uint64_t nonce;         // Random number used in mining
    uint32_t difficulty;    // Mining difficulty
    time_t timestamp;       // Block creation time
    string merkleRoot;      // Root hash of all transactions
    vector<string> transactions; // List of transactions in the block
    string hash;            // Hash of the block

    // Constructor to initialize a new block
    Block(string parentHash, vector<string> transactions, uint64_t nonce, uint32_t difficulty, time_t timestamp)
        : parentHash(move(parentHash)), transactions(move(transactions)), nonce(nonce), difficulty(difficulty), timestamp(timestamp) {
        this->merkleRoot = calculateMerkleRoot(this->transactions);
        this->hash = calculateHash();
    }

    // Computes the block hash
    string calculateHash() const {
        stringstream ss;
        ss << parentHash << merkleRoot << nonce << timestamp;
        return sha256(ss.str());
    }

    // Computes the Merkle Root for transactions
    static string calculateMerkleRoot(vector<string> transactions) {
        if (transactions.empty()) return "No transactions";
        if (transactions.size() == 1) return sha256(transactions[0]);

        while (transactions.size() > 1) {
            vector<string> newTransactions;
            for (size_t i = 0; i < transactions.size(); i += 2) {
                string combined = transactions[i];
                if (i + 1 < transactions.size()) {
                    combined += transactions[i + 1];
                }
                newTransactions.push_back(sha256(combined));
            }
            transactions = newTransactions;
        }
        return transactions[0];
    }

    // Displays block details
    void display() const {
        cout << "\n------ Block Details ------\n";
        cout << "Parent Hash: " << parentHash << endl;
        cout << "Merkle Root: " << merkleRoot << endl;
        cout << "Nonce: " << nonce << endl;
        cout << "Difficulty: " << difficulty << endl;
        cout << "Timestamp: " << timestamp << endl;
        cout << "Block Hash: " << hash << endl;
        cout << "---------------------------\n";
    }
};

// Blockchain class to manage blocks
class Blockchain {
private:
    vector<Block> chain;  // Stores all blocks in sequence
    unordered_map<string, Block*> blockMap;  // Quick lookup of blocks by hash

public:
    // Constructor to create the genesis block
    Blockchain() {
        time_t genesisTime = time(nullptr);
        Block genesisBlock("0", {"Genesis Tx1", "Genesis Tx2"}, 0, 1, genesisTime);
        chain.push_back(genesisBlock);
        blockMap[genesisBlock.hash] = &chain.back();
        cout << "Genesis block created:\n";
        chain.back().display();
    }

    // Get the latest block's hash (tip of the chain)
    string getTip() const {
        return chain.back().hash;
    }

    // Adds a new block to the blockchain
    void addBlock(vector<string> transactions) {
        time_t currentTime = time(nullptr);
        string parentHash = getTip();
        uint64_t nonce = rand() % 1000000;
        uint32_t difficulty = 1;

        Block newBlock(parentHash, transactions, nonce, difficulty, currentTime);
        chain.push_back(newBlock);
        blockMap[newBlock.hash] = &chain.back();

        cout << "\nNew block added:";
        chain.back().display();
    }

    // Displays all block hashes in the blockchain
    void displayBlockchain() const {
        cout << "\n------ Blockchain Blocks ------\n";
        for (const auto& block : chain) {
            cout << "Block Hash: " << block.hash << endl;
        }
        cout << "------------------------------\n";
    }
};

void miner(Blockchain& blockchain, int minerID) {
    for (int i = 0; i < 10; i++) {
        blockchain.addBlock({"tx1" + to_string(i), "tx2" + to_string(i)});
        this_thread::sleep_for(chrono::milliseconds(rand() % 1000));
    }
}

// Main function to simulate blockchain transactions
int main() {
    srand(time(0));
    Blockchain blockchain;

    // Add multiple blocks to the blockchain 
    vector<thread> threads;
    for (int i = 0; i < 5; i++)
    {
        threads.push_back(thread(miner, ref(blockchain), i + 1));
    }

    for (auto &th : threads)
    {
        th.join();
    }

    // Display all blockchain hashes
    blockchain.displayBlockchain();

    return 0;
}

// Output --->

// Genesis block created:

// ------ Block Details ------
// Parent Hash: 0
// Merkle Root: bda77aeae8bd80917f4777098075d8c7506a26fbd8f064d7df4c1f35befd2821
// Nonce: 0
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: cf4a75f2f8339221ca0ef5cbdd32a10ac7a33240d1a88b0443c9374b3e70dc7c
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: cf4a75f2f8339221ca0ef5cbdd32a10ac7a33240d1a88b0443c9374b3e70dc7c
// Merkle Root: 
// Nonce: 350322
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9ba264f3ca5d23ae55004200a96a3406de757fbfc1edee149c620b77aa2249c3
// Merkle Root: ac46020d72b7e5187776ad3b61b5450308a5b3d01ea7298d09eed8c7b5801fe5
// Nonce: 450234
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9ba264f3ca5d23ae55004200a96a3406de757fbfc1edee149c620b77aa2249c3
// Merkle Root: ac46020d72b7e5187776ad3b61b5450308a5b3d01ea7298d09eed8c7b5801fe5
// Nonce: 450234
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9ba264f3ca5d23ae55004200a96a3406de757fbfc1edee149c620b77aa2249c3
// Merkle Root: ac46020d72b7e5187776ad3b61b5450308a5b3d01ea7298d09eed8c7b5801fe5
// Nonce: 450234
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9ba264f3ca5d23ae55004200a96a3406de757fbfc1edee149c620b77aa2249c3
// Merkle Root: ac46020d72b7e5187776ad3b61b5450308a5b3d01ea7298d09eed8c7b5801fe5
// Nonce: 450234
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// Merkle Root: 6cf15f50096484c9c3421a35384f64c10aa190d3fa39ae4a02e9fcc17a3dbff4
// Nonce: 373404
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 7260cc425aa93106d6d965485ea765269f2d0128647630e66db8dc053e8d98ad
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7260cc425aa93106d6d965485ea765269f2d0128647630e66db8dc053e8d98ad
// Merkle Root: 6cf15f50096484c9c3421a35384f64c10aa190d3fa39ae4a02e9fcc17a3dbff4
// Nonce: 527774
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 525b5a7726a7000e30a8eeb6494449f62668d3a970c06177054e1d8f01e741e7
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 525b5a7726a7000e30a8eeb6494449f62668d3a970c06177054e1d8f01e741e7
// Merkle Root: 6cf15f50096484c9c3421a35384f64c10aa190d3fa39ae4a02e9fcc17a3dbff4
// Nonce: 111558
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 39f371701b715839bcf98ea78092e9fa2fffa8ce887da065d45f0e434e044102
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 39f371701b715839bcf98ea78092e9fa2fffa8ce887da065d45f0e434e044102
// Merkle Root: 6cf15f50096484c9c3421a35384f64c10aa190d3fa39ae4a02e9fcc17a3dbff4
// Nonce: 792233
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 8d1ab7a8d73d9dcad99c38c8a20f9b603df31b8318fdd5dfbec249998867e041
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 8d1ab7a8d73d9dcad99c38c8a20f9b603df31b8318fdd5dfbec249998867e041
// Merkle Root: cdb9d04983edc875b8d17eb6cf354e82b887e055b13ccea81cd8073a9c016642
// Nonce: 708212
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 0d679ec8d551105916b704034643eabb110fbe82a9287f9016976751142ba75c
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0d679ec8d551105916b704034643eabb110fbe82a9287f9016976751142ba75c
// Merkle Root: cdb9d04983edc875b8d17eb6cf354e82b887e055b13ccea81cd8073a9c016642
// Nonce: 532342
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 69df3d1216679c476c6c2c2bb2155169b7debb546d53dddf00d75caa2b0bbc74
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 69df3d1216679c476c6c2c2bb2155169b7debb546d53dddf00d75caa2b0bbc74
// Merkle Root: cdb9d04983edc875b8d17eb6cf354e82b887e055b13ccea81cd8073a9c016642
// Nonce: 77139
// Difficulty: 1
// Timestamp: 1738867393
// Block Hash: 7809b1c5d792be1064262f1b9cc89a59cf05b911fea7e921a9c5639871b6e667
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7809b1c5d792be1064262f1b9cc89a59cf05b911fea7e921a9c5639871b6e667
// Merkle Root: cdb9d04983edc875b8d17eb6cf354e82b887e055b13ccea81cd8073a9c016642
// Nonce: 784216
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: e09b1af1b9714e679ef8f1bbae3a681fe1d55a8a3e9fbfc4b57ff69e4e5d19c8
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e09b1af1b9714e679ef8f1bbae3a681fe1d55a8a3e9fbfc4b57ff69e4e5d19c8
// Merkle Root: 6cf15f50096484c9c3421a35384f64c10aa190d3fa39ae4a02e9fcc17a3dbff4
// Nonce: 426299
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: d9ee53f44f476c87ae247426047d1f6ec91e39f3934a8fd933b66dfd5e02068e
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: d9ee53f44f476c87ae247426047d1f6ec91e39f3934a8fd933b66dfd5e02068e
// Merkle Root: 6e7acd2b126f69696fd2a276afe6f9727f109eaf2b351013cebc08971c0c087b
// Nonce: 521994
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: 4d280915ffdee81e28ff7aa86d8800d3906678337407c4b4e97ef96ebd004de1
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 4d280915ffdee81e28ff7aa86d8800d3906678337407c4b4e97ef96ebd004de1
// Merkle Root: 6e7acd2b126f69696fd2a276afe6f9727f109eaf2b351013cebc08971c0c087b
// Nonce: 882944
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: 1cf6312cbf45409b0f76ba15d65e1e5c4e37baf78122938d17de23e826ed4a47
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 1cf6312cbf45409b0f76ba15d65e1e5c4e37baf78122938d17de23e826ed4a47
// Merkle Root: 6e7acd2b126f69696fd2a276afe6f9727f109eaf2b351013cebc08971c0c087b
// Nonce: 715154
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: e661c9e557f589ed490e558259e4e861fc2d04f203b251fc9871ef6d28fb774e
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e661c9e557f589ed490e558259e4e861fc2d04f203b251fc9871ef6d28fb774e
// Merkle Root: 6e7acd2b126f69696fd2a276afe6f9727f109eaf2b351013cebc08971c0c087b
// Nonce: 438312
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: c0860c1eb76e1bcd8399b14029346899aec742658f847895a68735a9f703930f
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: c0860c1eb76e1bcd8399b14029346899aec742658f847895a68735a9f703930f
// Merkle Root: cdb9d04983edc875b8d17eb6cf354e82b887e055b13ccea81cd8073a9c016642
// Nonce: 892070
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: 24dac643ad0628fa6f17234450c99ec18f64e15de1a8f4b7faef3c5df2abf2cb
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 24dac643ad0628fa6f17234450c99ec18f64e15de1a8f4b7faef3c5df2abf2cb
// Merkle Root: 41b7598fda2d87e44ac552fe7121798327bfd86ea7ccf0dc6064496d3856bbb3
// Nonce: 48495
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: bae6c9286be0afa0a24e0519fd93340030c227ea5a6e91f37513e156fbbb2085
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: bae6c9286be0afa0a24e0519fd93340030c227ea5a6e91f37513e156fbbb2085
// Merkle Root: 791a89eeb5a84a63437794a4af9aa82f7dd49051d850efbd56c7190ba049c2f8
// Nonce: 10891
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: 8d12fad0a4e1141548335b9b6fc0df316a21dcfd0670f9bd74088d5fa353769a
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 8d12fad0a4e1141548335b9b6fc0df316a21dcfd0670f9bd74088d5fa353769a
// Merkle Root: 41b7598fda2d87e44ac552fe7121798327bfd86ea7ccf0dc6064496d3856bbb3
// Nonce: 220047
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: 3f64ec77aec9a574d35a455606a321c8aa5478470c08ecf47b41cdf8920a4c6f
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 3f64ec77aec9a574d35a455606a321c8aa5478470c08ecf47b41cdf8920a4c6f
// Merkle Root: 41b7598fda2d87e44ac552fe7121798327bfd86ea7ccf0dc6064496d3856bbb3
// Nonce: 187869
// Difficulty: 1
// Timestamp: 1738867394
// Block Hash: e21eba83e776a93ee3b94504439c387b0f0c459634cb361b8658038174be2f90
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e21eba83e776a93ee3b94504439c387b0f0c459634cb361b8658038174be2f90
// Merkle Root: 41b7598fda2d87e44ac552fe7121798327bfd86ea7ccf0dc6064496d3856bbb3
// Nonce: 325290
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: 77514e795c8c696da580f4f184208dc8ebdc55749b08525705d555421e17235e
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 77514e795c8c696da580f4f184208dc8ebdc55749b08525705d555421e17235e
// Merkle Root: 791a89eeb5a84a63437794a4af9aa82f7dd49051d850efbd56c7190ba049c2f8
// Nonce: 588453
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: e7040676c879c5c0c9e7b8b169f9cf757fbf646dfbde69e734893efc2aada5f0
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e7040676c879c5c0c9e7b8b169f9cf757fbf646dfbde69e734893efc2aada5f0
// Merkle Root: 791a89eeb5a84a63437794a4af9aa82f7dd49051d850efbd56c7190ba049c2f8
// Nonce: 769958
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: 0ad582ba1b3c611a7c861e713aee6ce4f8d14ee1bbbe53bc70bf983685bcdfe9
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0ad582ba1b3c611a7c861e713aee6ce4f8d14ee1bbbe53bc70bf983685bcdfe9
// Merkle Root: 791a89eeb5a84a63437794a4af9aa82f7dd49051d850efbd56c7190ba049c2f8
// Nonce: 329341
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: bd5ed78ab6706334c326d284e2aa5fb7784852ba162c38deb0f98e8d05978039
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: bd5ed78ab6706334c326d284e2aa5fb7784852ba162c38deb0f98e8d05978039
// Merkle Root: d1568f343da104310719c38f89a89e1ad171d3fe114bfb37d97f7832561e692d
// Nonce: 769441
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: 24ec6a11890377cdfe74c80f23b53bf3e06a299666da42f085d38f374451692f
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 24ec6a11890377cdfe74c80f23b53bf3e06a299666da42f085d38f374451692f
// Merkle Root: 6e7acd2b126f69696fd2a276afe6f9727f109eaf2b351013cebc08971c0c087b
// Nonce: 495792
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: 7812759f1dfba4a8839e4013c686aa3ae88687c5056aaf9ebd130a531c9a4ecc
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7812759f1dfba4a8839e4013c686aa3ae88687c5056aaf9ebd130a531c9a4ecc
// Merkle Root: d1568f343da104310719c38f89a89e1ad171d3fe114bfb37d97f7832561e692d
// Nonce: 652573
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: af10924137fc93490eb4d185f0632e6c59136bc560b5243febbbe4b85c7ef2c1
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: af10924137fc93490eb4d185f0632e6c59136bc560b5243febbbe4b85c7ef2c1
// Merkle Root: b5c84ff2eb8a08bdc122f07d4de09062531e000f4a521f645538b88540a989b3
// Nonce: 38343
// Difficulty: 1
// Timestamp: 1738867395
// Block Hash: 0953cee31469d84227198dcdb2f92fe0ed39d89fb2606880d4d23edf3e63949c
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0953cee31469d84227198dcdb2f92fe0ed39d89fb2606880d4d23edf3e63949c
// Merkle Root: d1568f343da104310719c38f89a89e1ad171d3fe114bfb37d97f7832561e692d
// Nonce: 922807
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 9a4cfd63c7cfdf89247f475f24a8ed9dcc22f2b4c23788bc2688facb95d943c7
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9a4cfd63c7cfdf89247f475f24a8ed9dcc22f2b4c23788bc2688facb95d943c7
// Merkle Root: d1568f343da104310719c38f89a89e1ad171d3fe114bfb37d97f7832561e692d
// Nonce: 14506
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: ca9fef3210811deb152d31049cf924c77c9370281a769f8a045548966e6ad121
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: ca9fef3210811deb152d31049cf924c77c9370281a769f8a045548966e6ad121
// Merkle Root: b5c84ff2eb8a08bdc122f07d4de09062531e000f4a521f645538b88540a989b3
// Nonce: 467942
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: af4897b594fdf59717d39ddde2e357a06656fffb175902706d6a3d32d9db5bf8
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: af4897b594fdf59717d39ddde2e357a06656fffb175902706d6a3d32d9db5bf8
// Merkle Root: 41b7598fda2d87e44ac552fe7121798327bfd86ea7ccf0dc6064496d3856bbb3
// Nonce: 449084
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: f4210e3cf1192ddf6c1f98d3f599ad6b6341ede5c0c0677b82a052d252e26825
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: f4210e3cf1192ddf6c1f98d3f599ad6b6341ede5c0c0677b82a052d252e26825
// Merkle Root: b5c84ff2eb8a08bdc122f07d4de09062531e000f4a521f645538b88540a989b3
// Nonce: 290035
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 6a56c63a141965f42f6e02bc0e71755b669d280cfcf8a12deb4317c04dfa9771
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 6a56c63a141965f42f6e02bc0e71755b669d280cfcf8a12deb4317c04dfa9771
// Merkle Root: b3a8fa5e6c0537104481c81c4889558e807e24fa679ce4acd841759ae3147425
// Nonce: 454688
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 943383badc8c241690f45240416d6c4c3f7e1d3be2d85ca7c17c7dea4dc93729
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 943383badc8c241690f45240416d6c4c3f7e1d3be2d85ca7c17c7dea4dc93729
// Merkle Root: fc4b4b0c91a569e4f5910fe18c67a9e83f6fdce4a50f7890d3500b5c5c77317c
// Nonce: 514993
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 0bd6d52871a12dfbb9e512a3d7237266f9221c1e4bdb48109a5fd6f6d42c2679
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0bd6d52871a12dfbb9e512a3d7237266f9221c1e4bdb48109a5fd6f6d42c2679
// Merkle Root: 791a89eeb5a84a63437794a4af9aa82f7dd49051d850efbd56c7190ba049c2f8
// Nonce: 358040
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 5b66acc53feb3d6f3535be971d302b99d310f437bf755bb443a0e5f9918de112
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 5b66acc53feb3d6f3535be971d302b99d310f437bf755bb443a0e5f9918de112
// Merkle Root: b5c84ff2eb8a08bdc122f07d4de09062531e000f4a521f645538b88540a989b3
// Nonce: 139013
// Difficulty: 1
// Timestamp: 1738867396
// Block Hash: 34bdd508f83d9398a72a029ace75055f4bf8494247dcf402f18c1dcae82241d4
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 34bdd508f83d9398a72a029ace75055f4bf8494247dcf402f18c1dcae82241d4
// Merkle Root: b3a8fa5e6c0537104481c81c4889558e807e24fa679ce4acd841759ae3147425
// Nonce: 390138
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: a96a6aa8dcbf70b868c3cf2900bffbc0a06601da7044227c778deeb8b5c97069
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: a96a6aa8dcbf70b868c3cf2900bffbc0a06601da7044227c778deeb8b5c97069
// Merkle Root: d1568f343da104310719c38f89a89e1ad171d3fe114bfb37d97f7832561e692d
// Nonce: 99993
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: 4f5f950c7b3acacc5e4b7d4987680d54a912fcbae4069ba2ab7ac1ff382f6276
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 4f5f950c7b3acacc5e4b7d4987680d54a912fcbae4069ba2ab7ac1ff382f6276
// Merkle Root: b3a8fa5e6c0537104481c81c4889558e807e24fa679ce4acd841759ae3147425
// Nonce: 272421
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: 0caea393ed5f8cf3b670b04a4a00ec9f9f5d948b69a531ce8080d69ba5580581
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0caea393ed5f8cf3b670b04a4a00ec9f9f5d948b69a531ce8080d69ba5580581
// Merkle Root: b3a8fa5e6c0537104481c81c4889558e807e24fa679ce4acd841759ae3147425
// Nonce: 865741
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: 61c1a534c8fad252190902929dfc7a6e3e39af4d0fc64fcc4e7c783c2247bbcf
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 61c1a534c8fad252190902929dfc7a6e3e39af4d0fc64fcc4e7c783c2247bbcf
// Merkle Root: fc4b4b0c91a569e4f5910fe18c67a9e83f6fdce4a50f7890d3500b5c5c77317c
// Nonce: 65175
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: ca016bb4128f19aa6db7de512e9d9e00b6e3df6196055298eebf32c7a03dffac
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: ca016bb4128f19aa6db7de512e9d9e00b6e3df6196055298eebf32c7a03dffac
// Merkle Root: fc4b4b0c91a569e4f5910fe18c67a9e83f6fdce4a50f7890d3500b5c5c77317c
// Nonce: 818704
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: 0bb5f10e4cdaa7bffd1c458c14f36e90bcdeadda49c4d77373bbea836a4f8a6e
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 0bb5f10e4cdaa7bffd1c458c14f36e90bcdeadda49c4d77373bbea836a4f8a6e
// Merkle Root: b5c84ff2eb8a08bdc122f07d4de09062531e000f4a521f645538b88540a989b3
// Nonce: 86535
// Difficulty: 1
// Timestamp: 1738867397
// Block Hash: e95da489a3df3bcd7ea4b216add646d53fcca5be0c07ee0ad53744a13c09e54a
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e95da489a3df3bcd7ea4b216add646d53fcca5be0c07ee0ad53744a13c09e54a
// Merkle Root: fc4b4b0c91a569e4f5910fe18c67a9e83f6fdce4a50f7890d3500b5c5c77317c
// Nonce: 406073
// Difficulty: 1
// Timestamp: 1738867398
// Block Hash: df1919105bb956148d3058081447c8c1618f2ea91b6d708c94dc419b51fe205b
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: df1919105bb956148d3058081447c8c1618f2ea91b6d708c94dc419b51fe205b
// Merkle Root: b3a8fa5e6c0537104481c81c4889558e807e24fa679ce4acd841759ae3147425
// Nonce: 618984
// Difficulty: 1
// Timestamp: 1738867398
// Block Hash: 5de24042bf5b941c73a5edc723c39e9acc1a1fc37868e3e804db3a5411740430
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 5de24042bf5b941c73a5edc723c39e9acc1a1fc37868e3e804db3a5411740430
// Merkle Root: fc4b4b0c91a569e4f5910fe18c67a9e83f6fdce4a50f7890d3500b5c5c77317c
// Nonce: 523970
// Difficulty: 1
// Timestamp: 1738867398
// Block Hash: 3127b140a23151b7e6372246dff4a40e3f28c90ac0c1a9461b0d577a22e98da7
// ---------------------------

// ------ Blockchain Blocks ------
// Block Hash: cf4a75f2f8339221ca0ef5cbdd32a10ac7a33240d1a88b0443c9374b3e70dc7c
// Block Hash: 44f7627f638d541a1270d2ae3b33a0ff7727ebdc6533d98a85d1ce218758bb7b
// Block Hash: b57f650e2351ddf4838ac2e77fc7f9cffdc1c3ccb890cd585d8e5cda8e7e4970
// Block Hash: 4d463596f26b171baea81f9fbc205cc13cc0a7ab9b960bd9e12d6cdb29aee3b4
// Block Hash: 9ba264f3ca5d23ae55004200a96a3406de757fbfc1edee149c620b77aa2249c3
// Block Hash: f87c9e187b5d50d9f8fa3a05e17f629c2309042cac9c7617b9b5ff4cb85d3480
// Block Hash: 7260cc425aa93106d6d965485ea765269f2d0128647630e66db8dc053e8d98ad
// Block Hash: 525b5a7726a7000e30a8eeb6494449f62668d3a970c06177054e1d8f01e741e7
// Block Hash: 39f371701b715839bcf98ea78092e9fa2fffa8ce887da065d45f0e434e044102
// Block Hash: 8d1ab7a8d73d9dcad99c38c8a20f9b603df31b8318fdd5dfbec249998867e041
// Block Hash: 0d679ec8d551105916b704034643eabb110fbe82a9287f9016976751142ba75c
// Block Hash: 69df3d1216679c476c6c2c2bb2155169b7debb546d53dddf00d75caa2b0bbc74
// Block Hash: 7809b1c5d792be1064262f1b9cc89a59cf05b911fea7e921a9c5639871b6e667
// Block Hash: e09b1af1b9714e679ef8f1bbae3a681fe1d55a8a3e9fbfc4b57ff69e4e5d19c8
// Block Hash: d9ee53f44f476c87ae247426047d1f6ec91e39f3934a8fd933b66dfd5e02068e
// Block Hash: 4d280915ffdee81e28ff7aa86d8800d3906678337407c4b4e97ef96ebd004de1
// Block Hash: 1cf6312cbf45409b0f76ba15d65e1e5c4e37baf78122938d17de23e826ed4a47
// Block Hash: e661c9e557f589ed490e558259e4e861fc2d04f203b251fc9871ef6d28fb774e
// Block Hash: c0860c1eb76e1bcd8399b14029346899aec742658f847895a68735a9f703930f
// Block Hash: 24dac643ad0628fa6f17234450c99ec18f64e15de1a8f4b7faef3c5df2abf2cb
// Block Hash: bae6c9286be0afa0a24e0519fd93340030c227ea5a6e91f37513e156fbbb2085
// Block Hash: 8d12fad0a4e1141548335b9b6fc0df316a21dcfd0670f9bd74088d5fa353769a
// Block Hash: 3f64ec77aec9a574d35a455606a321c8aa5478470c08ecf47b41cdf8920a4c6f
// Block Hash: e21eba83e776a93ee3b94504439c387b0f0c459634cb361b8658038174be2f90
// Block Hash: 77514e795c8c696da580f4f184208dc8ebdc55749b08525705d555421e17235e
// Block Hash: e7040676c879c5c0c9e7b8b169f9cf757fbf646dfbde69e734893efc2aada5f0
// Block Hash: 0ad582ba1b3c611a7c861e713aee6ce4f8d14ee1bbbe53bc70bf983685bcdfe9
// Block Hash: bd5ed78ab6706334c326d284e2aa5fb7784852ba162c38deb0f98e8d05978039
// Block Hash: 24ec6a11890377cdfe74c80f23b53bf3e06a299666da42f085d38f374451692f
// Block Hash: 7812759f1dfba4a8839e4013c686aa3ae88687c5056aaf9ebd130a531c9a4ecc
// Block Hash: af10924137fc93490eb4d185f0632e6c59136bc560b5243febbbe4b85c7ef2c1
// Block Hash: 0953cee31469d84227198dcdb2f92fe0ed39d89fb2606880d4d23edf3e63949c
// Block Hash: 9a4cfd63c7cfdf89247f475f24a8ed9dcc22f2b4c23788bc2688facb95d943c7
// Block Hash: ca9fef3210811deb152d31049cf924c77c9370281a769f8a045548966e6ad121
// Block Hash: af4897b594fdf59717d39ddde2e357a06656fffb175902706d6a3d32d9db5bf8
// Block Hash: f4210e3cf1192ddf6c1f98d3f599ad6b6341ede5c0c0677b82a052d252e26825
// Block Hash: 6a56c63a141965f42f6e02bc0e71755b669d280cfcf8a12deb4317c04dfa9771
// Block Hash: 943383badc8c241690f45240416d6c4c3f7e1d3be2d85ca7c17c7dea4dc93729
// Block Hash: 0bd6d52871a12dfbb9e512a3d7237266f9221c1e4bdb48109a5fd6f6d42c2679
// Block Hash: 5b66acc53feb3d6f3535be971d302b99d310f437bf755bb443a0e5f9918de112
// Block Hash: 34bdd508f83d9398a72a029ace75055f4bf8494247dcf402f18c1dcae82241d4
// Block Hash: a96a6aa8dcbf70b868c3cf2900bffbc0a06601da7044227c778deeb8b5c97069
// Block Hash: 4f5f950c7b3acacc5e4b7d4987680d54a912fcbae4069ba2ab7ac1ff382f6276
// Block Hash: 0caea393ed5f8cf3b670b04a4a00ec9f9f5d948b69a531ce8080d69ba5580581
// Block Hash: 61c1a534c8fad252190902929dfc7a6e3e39af4d0fc64fcc4e7c783c2247bbcf
// Block Hash: ca016bb4128f19aa6db7de512e9d9e00b6e3df6196055298eebf32c7a03dffac
// Block Hash: 0bb5f10e4cdaa7bffd1c458c14f36e90bcdeadda49c4d77373bbea836a4f8a6e
// Block Hash: e95da489a3df3bcd7ea4b216add646d53fcca5be0c07ee0ad53744a13c09e54a
// Block Hash: df1919105bb956148d3058081447c8c1618f2ea91b6d708c94dc419b51fe205b
// Block Hash: 5de24042bf5b941c73a5edc723c39e9acc1a1fc37868e3e804db3a5411740430
// Block Hash: 3127b140a23151b7e6372246dff4a40e3f28c90ac0c1a9461b0d577a22e98da7
// ------------------------------
