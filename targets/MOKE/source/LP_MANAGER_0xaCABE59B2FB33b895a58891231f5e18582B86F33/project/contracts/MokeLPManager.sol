// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./interfaces/IMokeLPManager.sol";

interface IPancakeRouter02 {
    function WETH() external pure returns (address);
    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external payable returns (uint256 amountToken, uint256 amountETH, uint256 liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint256 liquidity,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB);
    function factory() external pure returns (address);
}

interface IWETH {
    function withdraw(uint256 wad) external;
}

interface IMokeTokenLP {
    function addReleasedBalance(address user, uint256 amount) external;
    function releasedMokeBalance(address user) external view returns (uint256);
}

interface IPancakeFactory {
    function getPair(address tokenA, address tokenB) external view returns (address);
}

/**
 * @title MokeLPManager
 * @dev LP management contract (pre-trading phase)
 * - Adds liquidity for users during participation
 * - Handles pre-trading LP removal with 5% MOKE fee
 * - Post-trading: users interact with PancakeSwap directly (tax handled by MokeToken)
 */
contract MokeLPManager is IMokeLPManager, Ownable, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    IERC20 public mokeToken;
    IPancakeRouter02 public router;
    IERC20 public lpToken;

    address public lpDividendPool;
    address public nftDividendPool;
    address public marketingWallet;

    uint256 public removeFeeRate = 500;
    uint256 public lpDivShare = 200;
    uint256 public nftDivShare = 200;
    uint256 public marketingShare = 100;
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public liquiditySlippageBps = 500;

    mapping(address => bool) public isAuthorized;

    event LiquidityAdded(address indexed user, uint256 mokeAmount, uint256 bnbAmount, uint256 lpAmount);
    event LiquidityRemoved(address indexed user, uint256 lpAmount, uint256 mokeReturned, uint256 bnbReturned, uint256 mokeFee);
    event AuthorizedSet(address indexed addr, bool status);
    event RemoveFeeRateSet(uint256 newRate);
    event FeeSharesSet(uint256 lpShare, uint256 nftShare, uint256 marketingShare_);
    event EmergencyWithdraw(address indexed token, uint256 amount);

    constructor(
        address _mokeToken,
        address _router,
        address _marketingWallet
    ) Ownable(msg.sender) {
        mokeToken = IERC20(_mokeToken);
        router = IPancakeRouter02(_router);
        marketingWallet = _marketingWallet;

        address factory = router.factory();
        address pair = IPancakeFactory(factory).getPair(_mokeToken, router.WETH());
        if (pair != address(0)) {
            lpToken = IERC20(pair);
        }
    }

    modifier onlyAuthorizedOrOwner() {
        require(isAuthorized[msg.sender] || msg.sender == owner(), "Not authorized");
        _;
    }

    function setAuthorized(address addr, bool status) external onlyOwner {
        isAuthorized[addr] = status;
        emit AuthorizedSet(addr, status);
    }

    function setLPToken(address _lpToken) external onlyOwner {
        lpToken = IERC20(_lpToken);
    }

    function setMokeToken(address _mokeToken) external onlyOwner {
        require(_mokeToken != address(0), "Invalid token");
        mokeToken = IERC20(_mokeToken);
    }

    function setRouter(address _router) external onlyOwner {
        require(_router != address(0), "Invalid router");
        router = IPancakeRouter02(_router);
    }

    function setDividendPools(address _lpPool, address _nftPool) external onlyOwner {
        lpDividendPool = _lpPool;
        nftDividendPool = _nftPool;
    }

    function setMarketingWallet(address _wallet) external onlyOwner {
        marketingWallet = _wallet;
    }

    function setRemoveFeeRate(uint256 _rate) external onlyOwner {
        require(_rate <= 2000, "Fee too high");
        removeFeeRate = _rate;
        emit RemoveFeeRateSet(_rate);
    }

    function setLiquiditySlippageBps(uint256 _bps) external onlyOwner {
        require(_bps <= 3000, "Max 30%");
        liquiditySlippageBps = _bps;
    }

    function setFeeShares(uint256 _lpShare, uint256 _nftShare, uint256 _marketingShare) external onlyOwner {
        require(_lpShare + _nftShare + _marketingShare > 0, "All zero");
        lpDivShare = _lpShare;
        nftDivShare = _nftShare;
        marketingShare = _marketingShare;
        emit FeeSharesSet(_lpShare, _nftShare, _marketingShare);
    }

    function addLiquidityForUser(
        address user,
        uint256 mokeAmount,
        uint256 bnbAmount
    ) external payable override onlyAuthorizedOrOwner returns (uint256 lpAmount) {
        require(msg.value >= bnbAmount, "Insufficient BNB");

        mokeToken.safeTransferFrom(msg.sender, address(this), mokeAmount);
        mokeToken.forceApprove(address(router), mokeAmount);

        uint256 amountTokenMin = mokeAmount * (BASIS_POINTS - liquiditySlippageBps) / BASIS_POINTS;
        uint256 amountETHMin = bnbAmount * (BASIS_POINTS - liquiditySlippageBps) / BASIS_POINTS;
        (,, uint256 lp) = router.addLiquidityETH{value: bnbAmount}(
            address(mokeToken),
            mokeAmount,
            amountTokenMin,
            amountETHMin,
            user,
            block.timestamp + 300
        );

        uint256 refund = msg.value - bnbAmount;
        if (refund > 0) {
            (bool sent,) = payable(msg.sender).call{value: refund}("");
            require(sent, "Refund failed");
        }

        emit LiquidityAdded(user, mokeAmount, bnbAmount, lp);
        return lp;
    }

    /**
     * @dev Remove liquidity: ALL MOKE is burned to 0xdead, user receives only BNB.
     *      Uses router.removeLiquidity (non-ETH) so pair sends tokens directly
     *      to LPManager (exempt address), bypassing LP burn detection in MokeToken.
     *      Then LPManager manually unwraps WETH → BNB for the user.
     */
    function removeLiquidity(uint256 lpAmount, uint256 minBnbOut) external override nonReentrant whenNotPaused {
        require(lpAmount > 0, "Zero LP");
        require(address(lpToken) != address(0), "LP not set");

        lpToken.safeTransferFrom(msg.sender, address(this), lpAmount);
        lpToken.forceApprove(address(router), lpAmount);

        address wethAddr = router.WETH();

        (uint256 mokeOut, uint256 wethOut) = router.removeLiquidity(
            address(mokeToken),
            wethAddr,
            lpAmount,
            0,
            minBnbOut,
            address(this),
            block.timestamp + 300
        );

        if (mokeOut > 0) {
            mokeToken.safeTransfer(address(0xdead), mokeOut);
        }

        if (wethOut > 0) {
            IWETH(wethAddr).withdraw(wethOut);
            (bool sent,) = payable(msg.sender).call{value: wethOut}("");
            require(sent, "BNB transfer failed");
        }

        emit LiquidityRemoved(msg.sender, lpAmount, 0, wethOut, mokeOut);
    }

    /**
     * @dev Add LP using released MOKE + user's BNB.
     *      Released MOKE is deducted by MokeToken._update (isReleasedMokeHandler check).
     *      If Router uses less MOKE than transferred, the excess is returned to user
     *      and the corresponding releasedMokeBalance is restored to prevent leakage.
     */
    function addLPWithReleasedMoke(
        uint256 mokeAmount
    ) external payable nonReentrant whenNotPaused {
        require(mokeAmount > 0 && msg.value > 0, "Zero input");

        uint256 releasedBefore = IMokeTokenLP(address(mokeToken)).releasedMokeBalance(msg.sender);

        mokeToken.safeTransferFrom(msg.sender, address(this), mokeAmount);

        uint256 releasedAfter = IMokeTokenLP(address(mokeToken)).releasedMokeBalance(msg.sender);
        uint256 releasedUsed = releasedBefore - releasedAfter;

        mokeToken.forceApprove(address(router), mokeAmount);

        uint256 amountTokenMin = mokeAmount * (BASIS_POINTS - liquiditySlippageBps) / BASIS_POINTS;
        uint256 amountETHMin = msg.value * (BASIS_POINTS - liquiditySlippageBps) / BASIS_POINTS;

        uint256 ethBefore = address(this).balance - msg.value;

        (uint256 amountToken,, uint256 lp) = router.addLiquidityETH{value: msg.value}(
            address(mokeToken),
            mokeAmount,
            amountTokenMin,
            amountETHMin,
            msg.sender,
            block.timestamp + 300
        );

        uint256 mokeRefund = mokeAmount - amountToken;
        if (mokeRefund > 0) {
            uint256 releasedRefund = mokeRefund > releasedUsed ? releasedUsed : mokeRefund;
            if (releasedRefund > 0) {
                IMokeTokenLP(address(mokeToken)).addReleasedBalance(msg.sender, releasedRefund);
            }
            mokeToken.safeTransfer(msg.sender, mokeRefund);
        }

        uint256 ethRefund = address(this).balance - ethBefore;
        if (ethRefund > 0) {
            (bool sent,) = payable(msg.sender).call{value: ethRefund}("");
            require(sent, "ETH refund failed");
        }

        emit LiquidityAdded(msg.sender, amountToken, msg.value - ethRefund, lp);
    }

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        if (token == address(0)) {
            (bool sent,) = payable(owner()).call{value: amount}("");
            require(sent, "BNB transfer failed");
        } else {
            IERC20(token).safeTransfer(owner(), amount);
        }
        emit EmergencyWithdraw(token, amount);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    receive() external payable {}
}
