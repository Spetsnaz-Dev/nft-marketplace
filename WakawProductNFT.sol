//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;
pragma abicoder v2; // required to accept structs as function parameters

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";

contract WakawProductNFT is ERC721URIStorage, EIP712, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    string private constant WAKAW_BRAND = "ProductNFT-Voucher";
    string private constant SIGNATURE_VERSION = "1";
    uint256 public totalSupply;
    uint256 public mintCost;
    address payable public wkwadmin;
    string public productId;
    uint256 public wkw_royalty;
    uint256 public brand_royalty;
    uint256 public designer_royalty;
    address payable public brand;
    uint256 public brandId;
    address payable public designer;
    uint256 public nftPrice;
    mapping(uint256 => uint256) public tokenIdToValue;
    mapping(uint256 => bool) public tokenIdForSale;
    mapping(uint256 => string) public _tokenURIs; // Mapping for token URIs
    mapping(address => uint256) pendingWithdrawals;
    // map cryptoboy's token id to crypto boy
    mapping(uint256 => NFTVoucher) public allNFTVoucher;

    event TokenPurchased(address account, uint256 amount, uint256 rate);
    event TokenSold(address account, uint256 amount, uint256 rate);
    event TokenTransfer(address account, address to, uint256 amount);

    constructor(
        address payable minter,
        address _brand,
        address _designer,
        string memory _productId,
        uint256 _wkw_royalty,
        uint256 _brand_royalty,
        uint256 _designer_royalty,
        uint256 _nftPrice,
        uint256 _totalSupply,
        string memory _tokenName,
        string memory _tokenSymbol
    ) EIP712(WAKAW_BRAND, SIGNATURE_VERSION) ERC721(_tokenName, _tokenSymbol) {
        // id = _id;
        brand = _brand;
        productId = _productId;
        totalSupply = _totalSupply;
        nftPrice = _nftPrice;
        mintCost = 0.00000000000001 ether; //mintiCommision fixed price
        designer = _designer;
        wkw_royalty = _wkw_royalty;
        brand_royalty = _brand_royalty;
        designer_royalty = _designer_royalty;
        _setupRole(MINTER_ROLE, minter);
    }

    modifier onlyAdmin() {
        require(msg.sender == wkwadmin);
        _;
    }

    modifier onlyBrand() {
        require(msg.sender == brand);
        _;
    }

    // @notice Represents an un-minted NFT, which has not yet been recorded into the blockchain. A signed voucher can be minted for a real NFT using the mint function.
    struct NFTVoucher {
        // @notice The id of the token to be minted. Must be unique - if another token with this ID already exists, the mint function will revert.
        uint256 tokenId;
        // @notice The minimum price (in wei) that the NFT creator is willing to accept for the initial sale of this NFT.
        uint256 minPrice;
        // @notice The metadata URI to associate with this token.
        string uri;
        // @notice the EIP-712 signature of all other fields in the NFTVoucher struct. For a voucher to be valid, it must be signed by an account with the MINTER_ROLE.

        address payable mintedBy;
        address payable currentOwner;
        address payable previousOwner;
        uint256 numberOfTransfers;
        bool forSale;
        bytes signature;
    }

    // @notice Redeems an NFTVoucher for an actual NFT, creating it in the process.
    /// @param minter The address of the account which will receive the NFT upon success.
    /// @param voucher A signed NFTVoucher that describes the NFT to be minted.
    function mint(address minter, NFTVoucher calldata voucher)
        public
        payable
        returns (uint256)
    {
        // make sure signature is valid and get the address of the signer
        address signer = _verify(voucher);

        // make sure that the signer is authorized to mint NFTs
        require(
            hasRole(MINTER_ROLE, minter),
            "Signature invalid or unauthorized"
        );

        // make sure that the minter is paying enough to cover the buyer's cost
        require(msg.value >= voucher.minPrice, "Insufficient funds to mint");

        // first assign the token to the signer, to establish provenance on-chain
        _mint(minter, voucher.tokenId);

        _setTokenURI(voucher.tokenId, voucher.uri);

        // transfer the token to the minter
        _transfer(minter, minter, voucher.tokenId);

        // record payment to signer's withdrawal balance
        //pendingWithdrawals[minter] += msg.value;

        NFTVoucher memory newNFTVoucher = NFTVoucher(
            voucher.tokenId,
            voucher.minPrice,
            voucher.uri,
            payable(minter),
            payable(minter),
            payable(address(0)),
            0,
            true,
            voucher.signature
        );

        allNFTVoucher[voucher.tokenId] = newNFTVoucher;
        return voucher.tokenId;
    }

    /// @notice Checks if nft is already minted
    function checkMinted(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    /// @notice Checks if given tokenId is available for to buy
    function availableToBuy(uint256 tokenId) public view returns (bool) {
        return tokenIdForSale[tokenId];
    }

    /// @notice Transfers all pending withdrawal balance to the caller. Reverts if the caller is not an authorized minter.
    function withdraw() public {
        require(
            hasRole(MINTER_ROLE, msg.sender),
            "Only authorized minters can withdraw"
        );

        address payable receiver = payable(msg.sender);
        uint256 amount = pendingWithdrawals[receiver];
        // zero account before transfer to prevent re-entrancy attack
        pendingWithdrawals[receiver] = 0;
        receiver.transfer(amount);
    }

    /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
    /// @param voucher An NFTVoucher to hash.
    function _hash(NFTVoucher calldata voucher)
        internal
        view
        returns (bytes32)
    {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "NFTVoucher(uint256 tokenId,uint256 minPrice,string uri)"
                        ),
                        voucher.tokenId,
                        voucher.minPrice,
                        keccak256(bytes(voucher.uri))
                    )
                )
            );
    }

    /// @notice Returns the chain id of the current blockchain.
    /// @dev This is used to workaround an issue with ganache returning different values from the on-chain chainid() function and
    ///  the eth_chainId RPC method. See https://github.com/protocol/nft-website/issues/121 for context.
    function getChainID() external view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @notice Verifies the signature for a given NFTVoucher, returning the address of the signer.
    /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
    /// @param voucher An NFTVoucher describing an unminted NFT.
    function _verify(NFTVoucher calldata voucher)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hash(voucher);
        return ECDSA.recover(digest, voucher.signature);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControl, ERC721)
        returns (bool)
    {
        return
            ERC721.supportsInterface(interfaceId) ||
            AccessControl.supportsInterface(interfaceId);
    }

    function setMintCost(uint256 newCost) public onlyBrand {
        mintCost = newCost;
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI)
        internal
        virtual
        override
    {
        require(
            _exists(tokenId),
            "ERC721Metadata: URI set of nonexistent token"
        );
        //require(bytes(_tokenURIs[t okenId]).length == 0,"ERC721Metadata token URI cannot be changed");
        _tokenURIs[tokenId] = _tokenURI;
    }

    function buyToken(uint256 _tokenId) public payable {
        require(msg.sender != address(0));
        require(_exists(_tokenId));
        address tokenOwner = ownerOf(_tokenId);
        require(tokenOwner != address(0));
        require(tokenOwner != msg.sender);
        NFTVoucher memory nftVoucher = allNFTVoucher[_tokenId];
        require(msg.value >= nftVoucher.minPrice);
        require(nftVoucher.forSale);
        _transfer(tokenOwner, msg.sender, _tokenId);
        // address payable brand = nftVoucher.currentOwner;
        nftVoucher.previousOwner = nftVoucher.currentOwner;
        nftVoucher.currentOwner = payable(msg.sender);
        nftVoucher.numberOfTransfers += 1;
        allNFTVoucher[_tokenId] = nftVoucher;

        // calculate royalty and transfer to respective royalty holders
        uint256 wakawRoyalty = (wkw_royalty * msg.value * 10**16);
        uint256 brandRoyalty = (brand_royalty * msg.value * 10**16);
        uint256 designerRoyalty = (designer_royalty * msg.value * 10**16);
        payable(wkwadmin).transfer(wakawRoyalty);
        payable(brand).transfer(brandRoyalty);
        payable(designer).transfer(designerRoyalty);
        emit TokenPurchased(msg.sender, nftVoucher.minPrice, nftPrice);
        emit TokenPurchased(msg.sender, nftVoucher.minPrice, wakawRoyalty);
        emit TokenPurchased(msg.sender, nftVoucher.minPrice, brandRoyalty);
        emit TokenPurchased(msg.sender, nftVoucher.minPrice, designerRoyalty);
    }

    function sellToken(uint256 _quantity) public payable {
        require(_quantity > 0, "Amount should be greater than zero");
        uint256 etherAmount = _quantity * nftPrice;
        require(
            balanceOf(brand) >= _quantity,
            "You can't sell more tokens than you have."
        );
        require(address(this).balance >= etherAmount);
        pendingWithdrawals[msg.sender] += _quantity;
        pendingWithdrawals[brand] -= _quantity;
        withdraw();
        emit TokenSold(msg.sender, _quantity, nftPrice);
    }

    function transferToken(address _to, uint256 _amount) public {
        require(
            balanceOf(msg.sender) >= _amount,
            "You can't transfer more tokens than you have."
        );
        pendingWithdrawals[msg.sender] -= _amount;
        pendingWithdrawals[brand] += _amount;
        emit TokenTransfer(msg.sender, _to, _amount);
    }
}
