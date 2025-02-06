#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <unordered_map>
#include <openssl/sha.h>

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

// Main function to simulate blockchain transactions
int main() {
    srand(time(0));
    Blockchain blockchain;

    // Add multiple blocks to the blockchain
    for (int i = 0; i < 50; i++) {
        blockchain.addBlock({"Tx" + to_string(i * 2 + 1), "Tx" + to_string(i * 2 + 2)});
    }

    // Display all blockchain hashes
    blockchain.displayBlockchain();

    return 0;
}


// Output---> 

// Genesis block created:

// ------ Block Details ------
// Parent Hash: 0
// Merkle Root: bda77aeae8bd80917f4777098075d8c7506a26fbd8f064d7df4c1f35befd2821
// Nonce: 0
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 31bd12d39ff629aa865598e6b1c708dea9870d943ceb38e9dd1ef4ea53422c55
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 31bd12d39ff629aa865598e6b1c708dea9870d943ceb38e9dd1ef4ea53422c55
// Merkle Root: 31b87e5cb3568d93552820e09ef9bb565beb48fddff819da84ed0f81c2b2869f
// Nonce: 860973
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: b8660b096018e009a4426c5fb1b0f0c6fcc52cb7657cf8cdb352da5d4474a707
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: b8660b096018e009a4426c5fb1b0f0c6fcc52cb7657cf8cdb352da5d4474a707
// Merkle Root: 8fdc5522c523bfc8c99dd9732919c13d68d784b66d87da2597a95d1b2538c2f6
// Nonce: 440617
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: d9f90b6e129a50ce187c72d9c590c13dc70c4f07040665f80703102c395461c2
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: d9f90b6e129a50ce187c72d9c590c13dc70c4f07040665f80703102c395461c2
// Merkle Root: fa076baa884d8acc0251b737d3b4de16dd77f26b27e4a7fe085f169d0c2d3148
// Nonce: 502481
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 1996a4cfb45bd290a3bd0510a3510475b6b2c557734927ec286afbcac4cf0554
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 1996a4cfb45bd290a3bd0510a3510475b6b2c557734927ec286afbcac4cf0554
// Merkle Root: c89b0692c073bdc086830f6fddb6b584eb7819bb1bf7c63a0481af8f57264155
// Nonce: 244743
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: e635e49243620c3d80dd7270cb9b9cd4dfcca8deb77b076680b7a4ee8797b791
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e635e49243620c3d80dd7270cb9b9cd4dfcca8deb77b076680b7a4ee8797b791
// Merkle Root: 9909e974d31eef0e926d1d37d90a2142fc0c39dbbf251c723888885e3d28a37d
// Nonce: 583671
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 7847caa6f774a4917a504d0488ff1bc9f2165711d77bbfad2c7e0f6d309ffce7
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7847caa6f774a4917a504d0488ff1bc9f2165711d77bbfad2c7e0f6d309ffce7
// Merkle Root: 9da1e48ccb8b8567f5ed64436da3a1bd725c9c7c1af1ff067b6486d49c56d27f
// Nonce: 811553
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: bfc095e45603437cccbf7cc95eed0c03c31df271e0891b82b9ef49ba820ac859
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: bfc095e45603437cccbf7cc95eed0c03c31df271e0891b82b9ef49ba820ac859
// Merkle Root: 88c7f83d91d4a0d26e522f155b7601f0e185f6b96d15547274b2b9738cb16e8a
// Nonce: 672625
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 99fa3321f324684464a400b41f0443b701c0c23fc6688fb58f2927ecdddea1f4
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 99fa3321f324684464a400b41f0443b701c0c23fc6688fb58f2927ecdddea1f4
// Merkle Root: ed7b01d32c5e0dfb2abf0e0bec90fc7aaed89f749881beff421aa96097cb1ac5
// Nonce: 780626
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: ca1b8e2b9a7c3cfadffe81dde90c3b6253e9069412d3a1dadfa7469b11f25a40
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: ca1b8e2b9a7c3cfadffe81dde90c3b6253e9069412d3a1dadfa7469b11f25a40
// Merkle Root: 17f501bfdeed0f7ebf0f46832e776c1fa8c5e69f3488cd5ccc90ce2718d5a325
// Nonce: 890026
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: ada08663f0aca5cc714cd691613431473cfe4745f7af4a43d69e6aa5dddf3e9d
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: ada08663f0aca5cc714cd691613431473cfe4745f7af4a43d69e6aa5dddf3e9d
// Merkle Root: d6e9196e9a006995ece621a6f3c4aeae1ab64442db7d4491e817d23b6d9d585d
// Nonce: 460403
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 06a4407fdbfd143cbf63caa055bc59dd71c968b810c3ad63d0281478acfd4493
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 06a4407fdbfd143cbf63caa055bc59dd71c968b810c3ad63d0281478acfd4493
// Merkle Root: 070785979288cc6796563a8896e69f3a4e0347e1d7f4ad1bbbbe948f4cb1d2ea
// Nonce: 837006
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: fc202971fef2a8135297031c24af8ddc3ea9f7d82dbc16837edc7470247838c9
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: fc202971fef2a8135297031c24af8ddc3ea9f7d82dbc16837edc7470247838c9
// Merkle Root: e7e1787fd61ad473664fef877b3284946df2652f95c4045fbea8f03b03bbbf10
// Nonce: 516211
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 83896ff92915f41dc992031c7e0133e753fc14c0c5ff46a59eabb6007886f3db
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 83896ff92915f41dc992031c7e0133e753fc14c0c5ff46a59eabb6007886f3db
// Merkle Root: 9c7940f99133233e02d18e7e7abab17dafd4b3f56dd5f62a13d52e54003696e6
// Nonce: 656343
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 27f8b3810d5efffe979b31f04010080cac7ecb628e7f214997b5656f63c6b191
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 27f8b3810d5efffe979b31f04010080cac7ecb628e7f214997b5656f63c6b191
// Merkle Root: 179fe3e73d00e9c47a92a4ae27ac0de9124fa9b156c25789c0b0f055c5801514
// Nonce: 324418
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 5a0ae05042afa2a395144caa831fba43e8d6a7428071ef5905b9ff4832b79c9c
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 5a0ae05042afa2a395144caa831fba43e8d6a7428071ef5905b9ff4832b79c9c
// Merkle Root: a562e68d261a48202d275a6ce6936ab93a499a24f7b78fa640bb07b70ab39945
// Nonce: 141165
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: a597a962e486187f82d0ab2b65e8288c93c80c26c30532396c4185bd42e035ce
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: a597a962e486187f82d0ab2b65e8288c93c80c26c30532396c4185bd42e035ce
// Merkle Root: 90c78f4479dc19c79570383244bc96e93524b053e82914c3146abe83a0143cdf
// Nonce: 663116
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 642f86d6351d855b02175773ad82750632356b21e2b63f8be1e75397fb6190cc
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 642f86d6351d855b02175773ad82750632356b21e2b63f8be1e75397fb6190cc
// Merkle Root: 833efc1e433c06992ea5b22e939a4d453c4798203272928f2e8d385e6be816cf
// Nonce: 179733
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: d889d245ffe783c5416fbd7cca3df6824665dbc03ac338b40e645e49ead194e5
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: d889d245ffe783c5416fbd7cca3df6824665dbc03ac338b40e645e49ead194e5
// Merkle Root: 6c8508024a82a4ff5fde08fbe88d9ad0a4ed393d015f7ded677f11a20ef32682
// Nonce: 124085
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 56794b556f86f9a4c98fd1abfbe8553d1400bcbf4b8f384f31dda0f6f7d688f3
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 56794b556f86f9a4c98fd1abfbe8553d1400bcbf4b8f384f31dda0f6f7d688f3
// Merkle Root: a8a10aba3c202924f155acdcc1351f5383191c133034a68f4a29cab6f10735ad
// Nonce: 924945
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 55e6949b6405eddf3ffb0417eec1dc4e5984a7a8b70e6e6951e28eaba01f37e0
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 55e6949b6405eddf3ffb0417eec1dc4e5984a7a8b70e6e6951e28eaba01f37e0
// Merkle Root: fd6a9f3bb52d1dc05be10e9deed2446ce0a32f2617dd30646d8a58aa8387c041
// Nonce: 763406
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 3fee17256c23bb7d668e0a47de362b3f81f73a2f1b97f0788b08f179a0cf1a50
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 3fee17256c23bb7d668e0a47de362b3f81f73a2f1b97f0788b08f179a0cf1a50
// Merkle Root: 87d60569bc804aef4b7db0b07462852af6c9bd3f1228a86f56191684dd26ab9f
// Nonce: 491410
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 83bc40d526dc839f041c21590718cb3189e68e4e40365a38390120ff4690f366
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 83bc40d526dc839f041c21590718cb3189e68e4e40365a38390120ff4690f366
// Merkle Root: dc88c1f83390aa65e3ba56792f9908f4790e45b501cc003e7f9d6c58f0eae803
// Nonce: 928646
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: f3fa1bdaec378599ba1ce079619d233a4b1562331ba11ea6ab41208f472e60a6
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: f3fa1bdaec378599ba1ce079619d233a4b1562331ba11ea6ab41208f472e60a6
// Merkle Root: 40557bf1593550b908765349dc9359075f2d10b38bc992d29239eb0083ef7820
// Nonce: 183893
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: ef5372b093fb10957729053797a3cd3517d9dfeb2d8ef74431f90fb80c1063cb
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: ef5372b093fb10957729053797a3cd3517d9dfeb2d8ef74431f90fb80c1063cb
// Merkle Root: b32f303e1f3a8e240704d5ef5b66cfead28139f20a052ee07c762c1666e5d662
// Nonce: 40043
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: a91e20c4b6123b48a3def4d36e2b27638e70b4332bf9f877705f0195fa87bfd9
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: a91e20c4b6123b48a3def4d36e2b27638e70b4332bf9f877705f0195fa87bfd9
// Merkle Root: 037a37acf6b21b4fe2da785c480b29c1aa310e28081b7fac3e0b34fd1fb5397c
// Nonce: 403158
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 9bcca4787258342bbfdadb1fbcefd31f3305997afe87193cc0a50f824583c1ed
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9bcca4787258342bbfdadb1fbcefd31f3305997afe87193cc0a50f824583c1ed
// Merkle Root: 92e8f18020b78cea167b4ba4436821c0f626f2356690e9e518cfb1226f1249e0
// Nonce: 799149
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 7be205140999271ade1251c02f0a0db6698a64c6092e5cf1d5d7911964bb21fb
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7be205140999271ade1251c02f0a0db6698a64c6092e5cf1d5d7911964bb21fb
// Merkle Root: dc86d924dfc35388aede3344d0534f91ff1716c95e281bddd6b3516f57be6412
// Nonce: 579060
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 80b8fba5749dec21c343e9c5503dc7f1e7c17d5aa674795204708c350a1c3422
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 80b8fba5749dec21c343e9c5503dc7f1e7c17d5aa674795204708c350a1c3422
// Merkle Root: 59b734dde275dbc335589b7d56ebac1de533e68edc8d074d61e0366e09c34462
// Nonce: 618918
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: b9489bf7e37902b76b2ed0e8ac3225fdb97591d22eab2e9bb8348ddd4c390a99
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: b9489bf7e37902b76b2ed0e8ac3225fdb97591d22eab2e9bb8348ddd4c390a99
// Merkle Root: d2deb478ddf10a9325d87cfab7b97c91b678372f316203e64d2284f15999a922
// Nonce: 508282
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 61aa2789ba20af46e8a1d2ba167b42f213ab47358d8fb9c5232b416d0989df6a
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 61aa2789ba20af46e8a1d2ba167b42f213ab47358d8fb9c5232b416d0989df6a
// Merkle Root: d169b21553ebe835c647f2087738b9efda191530f3b4c3cb72c19d7e42616229
// Nonce: 807878
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 918088c0d93f74fa79029856d29718dc97f1e5af3498fb2acfa0c8b48dc8ab76
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 918088c0d93f74fa79029856d29718dc97f1e5af3498fb2acfa0c8b48dc8ab76
// Merkle Root: 7734a468edcb001392c5fb0298ecbcbed6f3deaa277ef4476fb629494ac2a0a9
// Nonce: 258976
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: fb5a7370c10f6a255cc9d784ea62afea921f8eaef43da959788305f59128fa74
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: fb5a7370c10f6a255cc9d784ea62afea921f8eaef43da959788305f59128fa74
// Merkle Root: 25ba67d2ad11bd41b209d835164abf1ff03ad2c3a69ccc1c737fcf6d807b7ad2
// Nonce: 369255
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: e89aff544daed7107da512a05500f8fc2eafc31d6fd16461a8ee86cb4ad69b4a
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e89aff544daed7107da512a05500f8fc2eafc31d6fd16461a8ee86cb4ad69b4a
// Merkle Root: e0b46b8a1e76c7710dc39901b4f20ddde0590df078450c3475d78224af6294c5
// Nonce: 248495
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 93b93e5e3a50542586f8a38bd284f7cba15be643bda1483421d7f10e599d11ad
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 93b93e5e3a50542586f8a38bd284f7cba15be643bda1483421d7f10e599d11ad
// Merkle Root: f49e4f8be516aa4ab9c14a8a2490f289d3c2bfc5ca539afc61f24769f15134a9
// Nonce: 761457
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 2a05e21f882adc23cb9b20f1fb0917e211722b7f300220a75c38836b6de7ee24
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 2a05e21f882adc23cb9b20f1fb0917e211722b7f300220a75c38836b6de7ee24
// Merkle Root: 5a36eb0c90ac3645682fce52cd07f82fc8bce6c8bdf2e8754e013f193f4baceb
// Nonce: 130350
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: fce56ebdbb2754278efe45ed8bc238ff14dc997c7f2fd19c6124de6794136478
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: fce56ebdbb2754278efe45ed8bc238ff14dc997c7f2fd19c6124de6794136478
// Merkle Root: 0fb447d4413e86bd3410a3df6ed1781ce43782816831d02146ce5c47f11540fc
// Nonce: 348519
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: cc273d9f0ed8c5ff792aff11789a11f57ba3bf2470000ff1c2d19220f37dc027
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: cc273d9f0ed8c5ff792aff11789a11f57ba3bf2470000ff1c2d19220f37dc027
// Merkle Root: 792860f287cfb2217d11003de9f711a49b4e3de59071ded03b6bc86fef42855f
// Nonce: 573010
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 53403bc4d0a97b27d56e4efe140c74201681b2591bd4b718435b342195268bab
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 53403bc4d0a97b27d56e4efe140c74201681b2591bd4b718435b342195268bab
// Merkle Root: 53da3a10f8a461852d8ded815ac6594191537f654b86b6c396cc4b6c2640bbc5
// Nonce: 802976
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 65784a1467238ad40b6e978890ba7ac64c68989dee92eb5c5fbb7ef29facb0c0
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 65784a1467238ad40b6e978890ba7ac64c68989dee92eb5c5fbb7ef29facb0c0
// Merkle Root: a2265c1c5825cb28097e97ff5da38b7fdcab0c30991daba6b9b2e1008746edf8
// Nonce: 645497
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 5ad62acc51d27b28c21b5152de9c513585c611e2208a2ede65a4538b7227eceb
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 5ad62acc51d27b28c21b5152de9c513585c611e2208a2ede65a4538b7227eceb
// Merkle Root: 90a4a47b08a4af603d9b8f19937ba56dde233cfd9c5fd95e012e856f8d4ac7b0
// Nonce: 463036
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: f1bea24df89061790c1e362dd62ffa374bb73d6e66ed715491aec86020433658
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: f1bea24df89061790c1e362dd62ffa374bb73d6e66ed715491aec86020433658
// Merkle Root: 39189506997352e8cea98e599b9b9b2563fac2a849ad986d219f9a55d8de981d
// Nonce: 779731
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 7552f2f00dac271001eac6afd5d3c023c6b5ece0e6a38b57eb483f5022738340
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7552f2f00dac271001eac6afd5d3c023c6b5ece0e6a38b57eb483f5022738340
// Merkle Root: 95300a222e5fd69f3ea416e697cef61270b8f5a5d4f217078291415328bf2f34
// Nonce: 998855
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 9842e0604a21056eb9c4baf383d93da780b396afb91bcfd0577284402a03f2be
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 9842e0604a21056eb9c4baf383d93da780b396afb91bcfd0577284402a03f2be
// Merkle Root: b73088ac69ee076eaffeaa9ddca1bc48dc2267b20d6923fd6e1960f4b2d4c79b
// Nonce: 495600
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 7b14a84527ba883947352e674299d56b582d31d592c949d659b6ff3b50787b9b
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 7b14a84527ba883947352e674299d56b582d31d592c949d659b6ff3b50787b9b
// Merkle Root: 70275451a14fd2d7e539de8f17e14c2cf989f4c1b5084ded33d31ab3981575b1
// Nonce: 952427
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: f32678ec0eb9738a1cbfd4b73ae4c469c62ffcb74cc7736adedb2c52231331a3
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: f32678ec0eb9738a1cbfd4b73ae4c469c62ffcb74cc7736adedb2c52231331a3
// Merkle Root: 3b5777c1c865a1abac857791a7d29a24a4f3af88b95c1231fd9ee1645a826a8e
// Nonce: 323273
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 1a3ead8a40f637cc9945eb21802e8d062dcc7c1085d35b38e7785145577daaa1
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 1a3ead8a40f637cc9945eb21802e8d062dcc7c1085d35b38e7785145577daaa1
// Merkle Root: a1d25c462ad05e32df008ac61fb04f5a450857ddaa8ccc1aee38115fa041f298
// Nonce: 636765
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: b1ff53f13acc3e5de46b56e9ca093db2d50d6d2d822c77c5826ef1921d6c98c6
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: b1ff53f13acc3e5de46b56e9ca093db2d50d6d2d822c77c5826ef1921d6c98c6
// Merkle Root: f6c7e0d7ac46cf35d6addbe39f299e549b8636465052e4b0c50364104be75896
// Nonce: 131895
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: e6ec4de360bf73823c5d4dc159ae42b22c7be0369e4b8864be886ec57f611fc8
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: e6ec4de360bf73823c5d4dc159ae42b22c7be0369e4b8864be886ec57f611fc8
// Merkle Root: e6ae314df522b2d6c0f9eb9c3e755ba2468f3e491bb58b211eee18a69fd2343d
// Nonce: 19358
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: fa80ad00967b55e1a05247a74ff20d8a1c5c45a31551f047e25c03dfb9d3d4e0
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: fa80ad00967b55e1a05247a74ff20d8a1c5c45a31551f047e25c03dfb9d3d4e0
// Merkle Root: 889691c96db9a17c69f9c11a304cd7c10d18bd0f9cfda7449ec8d4610034309c
// Nonce: 277202
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 26de7abc733bd32a3f78f56c8690290cd6be797a11c4bc219c7ba937f3e355e4
// ---------------------------

// New block added:
// ------ Block Details ------
// Parent Hash: 26de7abc733bd32a3f78f56c8690290cd6be797a11c4bc219c7ba937f3e355e4
// Merkle Root: fc6067e6e2c6fc5cc2eb1d8de46369ee2fabe6978a2df6e4937e2165093b324c
// Nonce: 56841
// Difficulty: 1
// Timestamp: 1738866782
// Block Hash: 0a5eb85b777d87bf79049cb3a6b6146b83b0b46012311b8b9f9403b8e79bfb48
// ---------------------------

// ------ Blockchain Blocks ------
// Block Hash: 31bd12d39ff629aa865598e6b1c708dea9870d943ceb38e9dd1ef4ea53422c55
// Block Hash: b8660b096018e009a4426c5fb1b0f0c6fcc52cb7657cf8cdb352da5d4474a707
// Block Hash: d9f90b6e129a50ce187c72d9c590c13dc70c4f07040665f80703102c395461c2
// Block Hash: 1996a4cfb45bd290a3bd0510a3510475b6b2c557734927ec286afbcac4cf0554
// Block Hash: e635e49243620c3d80dd7270cb9b9cd4dfcca8deb77b076680b7a4ee8797b791
// Block Hash: 7847caa6f774a4917a504d0488ff1bc9f2165711d77bbfad2c7e0f6d309ffce7
// Block Hash: bfc095e45603437cccbf7cc95eed0c03c31df271e0891b82b9ef49ba820ac859
// Block Hash: 99fa3321f324684464a400b41f0443b701c0c23fc6688fb58f2927ecdddea1f4
// Block Hash: ca1b8e2b9a7c3cfadffe81dde90c3b6253e9069412d3a1dadfa7469b11f25a40
// Block Hash: ada08663f0aca5cc714cd691613431473cfe4745f7af4a43d69e6aa5dddf3e9d
// Block Hash: 06a4407fdbfd143cbf63caa055bc59dd71c968b810c3ad63d0281478acfd4493
// Block Hash: fc202971fef2a8135297031c24af8ddc3ea9f7d82dbc16837edc7470247838c9
// Block Hash: 83896ff92915f41dc992031c7e0133e753fc14c0c5ff46a59eabb6007886f3db
// Block Hash: 27f8b3810d5efffe979b31f04010080cac7ecb628e7f214997b5656f63c6b191
// Block Hash: 5a0ae05042afa2a395144caa831fba43e8d6a7428071ef5905b9ff4832b79c9c
// Block Hash: a597a962e486187f82d0ab2b65e8288c93c80c26c30532396c4185bd42e035ce
// Block Hash: 642f86d6351d855b02175773ad82750632356b21e2b63f8be1e75397fb6190cc
// Block Hash: d889d245ffe783c5416fbd7cca3df6824665dbc03ac338b40e645e49ead194e5
// Block Hash: 56794b556f86f9a4c98fd1abfbe8553d1400bcbf4b8f384f31dda0f6f7d688f3
// Block Hash: 55e6949b6405eddf3ffb0417eec1dc4e5984a7a8b70e6e6951e28eaba01f37e0
// Block Hash: 3fee17256c23bb7d668e0a47de362b3f81f73a2f1b97f0788b08f179a0cf1a50
// Block Hash: 83bc40d526dc839f041c21590718cb3189e68e4e40365a38390120ff4690f366
// Block Hash: f3fa1bdaec378599ba1ce079619d233a4b1562331ba11ea6ab41208f472e60a6
// Block Hash: ef5372b093fb10957729053797a3cd3517d9dfeb2d8ef74431f90fb80c1063cb
// Block Hash: a91e20c4b6123b48a3def4d36e2b27638e70b4332bf9f877705f0195fa87bfd9
// Block Hash: 9bcca4787258342bbfdadb1fbcefd31f3305997afe87193cc0a50f824583c1ed
// Block Hash: 7be205140999271ade1251c02f0a0db6698a64c6092e5cf1d5d7911964bb21fb
// Block Hash: 80b8fba5749dec21c343e9c5503dc7f1e7c17d5aa674795204708c350a1c3422
// Block Hash: b9489bf7e37902b76b2ed0e8ac3225fdb97591d22eab2e9bb8348ddd4c390a99
// Block Hash: 61aa2789ba20af46e8a1d2ba167b42f213ab47358d8fb9c5232b416d0989df6a
// Block Hash: 918088c0d93f74fa79029856d29718dc97f1e5af3498fb2acfa0c8b48dc8ab76
// Block Hash: fb5a7370c10f6a255cc9d784ea62afea921f8eaef43da959788305f59128fa74
// Block Hash: e89aff544daed7107da512a05500f8fc2eafc31d6fd16461a8ee86cb4ad69b4a
// Block Hash: 93b93e5e3a50542586f8a38bd284f7cba15be643bda1483421d7f10e599d11ad
// Block Hash: 2a05e21f882adc23cb9b20f1fb0917e211722b7f300220a75c38836b6de7ee24
// Block Hash: fce56ebdbb2754278efe45ed8bc238ff14dc997c7f2fd19c6124de6794136478
// Block Hash: cc273d9f0ed8c5ff792aff11789a11f57ba3bf2470000ff1c2d19220f37dc027
// Block Hash: 53403bc4d0a97b27d56e4efe140c74201681b2591bd4b718435b342195268bab
// Block Hash: 65784a1467238ad40b6e978890ba7ac64c68989dee92eb5c5fbb7ef29facb0c0
// Block Hash: 5ad62acc51d27b28c21b5152de9c513585c611e2208a2ede65a4538b7227eceb
// Block Hash: f1bea24df89061790c1e362dd62ffa374bb73d6e66ed715491aec86020433658
// Block Hash: 7552f2f00dac271001eac6afd5d3c023c6b5ece0e6a38b57eb483f5022738340
// Block Hash: 9842e0604a21056eb9c4baf383d93da780b396afb91bcfd0577284402a03f2be
// Block Hash: 7b14a84527ba883947352e674299d56b582d31d592c949d659b6ff3b50787b9b
// Block Hash: f32678ec0eb9738a1cbfd4b73ae4c469c62ffcb74cc7736adedb2c52231331a3
// Block Hash: 1a3ead8a40f637cc9945eb21802e8d062dcc7c1085d35b38e7785145577daaa1
// Block Hash: b1ff53f13acc3e5de46b56e9ca093db2d50d6d2d822c77c5826ef1921d6c98c6
// Block Hash: e6ec4de360bf73823c5d4dc159ae42b22c7be0369e4b8864be886ec57f611fc8
// Block Hash: fa80ad00967b55e1a05247a74ff20d8a1c5c45a31551f047e25c03dfb9d3d4e0
// Block Hash: 26de7abc733bd32a3f78f56c8690290cd6be797a11c4bc219c7ba937f3e355e4
// Block Hash: 0a5eb85b777d87bf79049cb3a6b6146b83b0b46012311b8b9f9403b8e79bfb48
// ------------------------------
