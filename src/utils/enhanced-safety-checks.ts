/**
 * Enhanced Safety Checks for Pocket Network MCP
 * Prevents context overflow and session crashes from large responses
 */

export interface SafetyCheckResult {
  safe: boolean;
  reason?: string;
  suggestion?: string;
}

export interface SafetyConfig {
  maxTransactionsPerBlock: number;
  maxBlockRange: number;
  maxResponseSizeEstimate: number; // in KB
  allowBlocksWithTransactions: boolean;
}

export const DEFAULT_SAFETY_CONFIG: SafetyConfig = {
  maxTransactionsPerBlock: 10,
  maxBlockRange: 10,
  maxResponseSizeEstimate: 500, // 500 KB max response
  allowBlocksWithTransactions: false, // CRITICAL: Block by default
};

/**
 * Dangerous RPC methods that can cause context overflow
 */
const DANGEROUS_METHODS = new Set([
  'eth_getBlockByNumber',
  'eth_getBlockByHash',
  'eth_getLogs',
  'eth_getTransactionReceipt', // Can be large with many logs
  'debug_traceTransaction', // Extremely large responses
  'trace_block', // Traces entire block
  'trace_transaction',
]);

/**
 * Methods that require special handling for address transaction history
 */
const TRANSACTION_HISTORY_PATTERNS = [
  /get.*transaction.*for.*address/i,
  /transaction.*history/i,
  /recent.*transactions/i,
  /last.*transaction/i,
  /latest.*transaction.*on.*address/i,
  /address.*transactions/i,
];

/**
 * Check if a natural language query is asking for transaction history
 */
export function isTransactionHistoryQuery(query: string): boolean {
  return TRANSACTION_HISTORY_PATTERNS.some(pattern => pattern.test(query));
}

/**
 * Check if an RPC method is dangerous
 */
export function isDangerousMethod(method: string): boolean {
  return DANGEROUS_METHODS.has(method);
}

/**
 * Validate block query safety
 */
export function checkBlockQuery(
  method: string,
  params: any[],
  config: SafetyConfig = DEFAULT_SAFETY_CONFIG
): SafetyCheckResult {
  // Check if requesting full transactions
  if (method === 'eth_getBlockByNumber' || method === 'eth_getBlockByHash') {
    const includeTransactions = params[1] === true;
    
    if (includeTransactions && !config.allowBlocksWithTransactions) {
      return {
        safe: false,
        reason: 'Requesting blocks with full transactions is disabled to prevent context overflow',
        suggestion: 'Use eth_getBlockByNumber with false parameter to get block without transactions, or query specific transactions by hash'
      };
    }
    
    if (includeTransactions) {
      return {
        safe: false,
        reason: 'Blocks can contain 100+ transactions, causing session crashes',
        suggestion: 'Query specific transactions by hash instead, or use a block explorer API'
      };
    }
  }
  
  return { safe: true };
}

/**
 * Validate log query safety
 */
export function checkLogQuery(
  params: any[],
  config: SafetyConfig = DEFAULT_SAFETY_CONFIG
): SafetyCheckResult {
  if (!params[0]) {
    return { safe: true };
  }
  
  const filter = params[0];
  const fromBlock = filter.fromBlock;
  const toBlock = filter.toBlock || 'latest';
  
  // Check block range
  if (fromBlock && toBlock && toBlock !== 'latest') {
    try {
      const from = typeof fromBlock === 'string' ? parseInt(fromBlock, 16) : fromBlock;
      const to = typeof toBlock === 'string' ? parseInt(toBlock, 16) : toBlock;
      const range = to - from;
      
      if (range > config.maxBlockRange) {
        return {
          safe: false,
          reason: `Block range ${range} exceeds maximum ${config.maxBlockRange}`,
          suggestion: 'Reduce the block range or use pagination'
        };
      }
    } catch (e) {
      // If we can't parse, be conservative
      return {
        safe: false,
        reason: 'Unable to validate block range safety',
        suggestion: 'Specify explicit numeric block ranges'
      };
    }
  }
  
  // Warn about unrestricted queries
  if (!filter.address && !filter.topics) {
    return {
      safe: false,
      reason: 'Unrestricted log queries can return massive amounts of data',
      suggestion: 'Add address or topic filters to limit results'
    };
  }
  
  return { safe: true };
}

/**
 * Main safety check for RPC calls
 */
export function validateRPCCall(
  blockchain: string,
  method: string,
  params: any[],
  config: SafetyConfig = DEFAULT_SAFETY_CONFIG
): SafetyCheckResult {
  // Check for dangerous methods
  if (isDangerousMethod(method)) {
    if (method.startsWith('eth_getBlock')) {
      return checkBlockQuery(method, params, config);
    }
    
    if (method === 'eth_getLogs') {
      return checkLogQuery(params, config);
    }
    
    // Other dangerous methods - block by default
    return {
      safe: false,
      reason: `Method ${method} can return extremely large responses`,
      suggestion: 'Use safer alternatives or fetch data from a block explorer API'
    };
  }
  
  return { safe: true };
}

/**
 * Check natural language query safety
 */
export function validateNaturalLanguageQuery(
  query: string,
  config: SafetyConfig = DEFAULT_SAFETY_CONFIG
): SafetyCheckResult {
  // Check for transaction history queries
  if (isTransactionHistoryQuery(query)) {
    return {
      safe: false,
      reason: 'Transaction history queries require fetching multiple blocks with full transaction data, which causes context overflow',
      suggestion: 'Instead:\n' +
                 '  • Query a specific transaction by hash if you know it\n' +
                 '  • Use a block explorer API (Etherscan, etc.) for transaction history\n' +
                 '  • Ask for current balance or state instead of history'
    };
  }
  
  // Check for patterns that might lead to large responses
  const dangerousPatterns = [
    /get all transactions/i,
    /list all/i,
    /fetch all/i,
    /every transaction/i,
    /all.*logs/i,
  ];
  
  for (const pattern of dangerousPatterns) {
    if (pattern.test(query)) {
      return {
        safe: false,
        reason: 'Query requests potentially unbounded data',
        suggestion: 'Add specific limits, filters, or time ranges to your query'
      };
    }
  }
  
  return { safe: true };
}

/**
 * Estimate response size for a query (conservative)
 */
export function estimateResponseSize(
  method: string,
  params: any[]
): number {
  // Size estimates in KB
  const estimates: Record<string, number> = {
    'eth_getBlockByNumber': params[1] === true ? 500 : 5,
    'eth_getBlockByHash': params[1] === true ? 500 : 5,
    'eth_getLogs': 200, // Very conservative
    'eth_getTransactionReceipt': 10,
    'debug_traceTransaction': 1000,
    'trace_block': 2000,
  };
  
  return estimates[method] || 5; // Default to 5KB for unknown methods
}

/**
 * Safe alternatives for common dangerous queries
 */
export const SAFE_ALTERNATIVES = {
  'get_last_transaction': 'Use a block explorer API like Etherscan to fetch recent transactions for an address',
  'get_transaction_history': 'Use etherscan.io API or similar indexing service',
  'get_all_logs': 'Add specific address and topic filters, limit block range to < 10 blocks',
  'get_block_with_transactions': 'Get block metadata only, then query specific transactions by hash',
};
