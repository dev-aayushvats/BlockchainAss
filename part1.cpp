#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <unordered_map>
#include <openssl/sha.h>

using namespace std;

string sha256(const string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str.c_str(), str.size(), hash);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class Block {
public:
    string parentHash;
    int nonce;
    int difficulty;
    time_t timestamp;
    vector<string> transactions;
    string merkleRoot;
    string hash;

    Block(string parentHash, vector<string> transactions, int difficulty) {
        this->parentHash = parentHash;
        this->nonce = rand() % 1000000;
        this->difficulty = difficulty;
        this->timestamp = time(0);
        this->transactions = transactions;
        this->merkleRoot = calculateMerkleRoot(transactions);
        this->hash = calculateHash();
    }

    static string calculateMerkleRoot(const vector<string>& transactions) {
        string concatenated;
        for (const auto& tx : transactions) {
            concatenated += tx;
        }
        return sha256(concatenated);
    }

    string calculateHash() const {
        stringstream ss;
        ss << parentHash << nonce << difficulty << timestamp << merkleRoot;
        return sha256(ss.str());
    }

    void display() const {
        cout << "Parent Hash: " << parentHash << endl;
        cout << "Nonce: " << nonce << endl;
        cout << "Difficulty: " << difficulty << endl;
        cout << "Timestamp: " << timestamp << endl;
        cout << "Merkle Root: " << merkleRoot << endl;
        cout << "Block Hash: " << hash << "\n" << endl;
    }
};

class Blockchain {
private:
    unordered_map<string, Block*> chain;
    string tip;

public:
    Blockchain() {
        Block* genesisBlock = new Block(string(64, '0'), {"Genesis Tx1", "Genesis Tx2"}, 1);
        chain[genesisBlock->hash] = genesisBlock;
        tip = genesisBlock->hash;
        cout << "Genesis block created:" << endl;
        genesisBlock->display();
    }

    void addBlock(const vector<string>& transactions) {
        Block* newBlock = new Block(tip, transactions, 1);
        chain[newBlock->hash] = newBlock;
        tip = newBlock->hash;
        cout << "Block added:" << endl;
        newBlock->display();
    }

    void displayBlock(const Block& block) const {
        block.display();
    }

    void displayBlockchainHashes() const {
        // cout << "Blockchain Hashes:" << endl;
        for (const auto& pair : chain) {
            cout << "Block Hash: " << pair.first << endl;
        }
    }

    string getTip() const {
        return tip;
    }
};

int main() {
    srand(time(0));
    Blockchain blockchain;

    for (int i = 0; i < 50; i++) {
        blockchain.addBlock({"Tx" + to_string(i * 2 + 1), "Tx" + to_string(i * 2 + 2)});
    }

    cout << "Current Tip of Blockchain: " << blockchain.getTip() << endl;
    blockchain.displayBlockchainHashes();
    
    return 0;
}
