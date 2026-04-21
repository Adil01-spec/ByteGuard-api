const axios = require('axios');
const logger = require('../utils/logger');

class CurrencyService {
  constructor() {
    this.rates = { USD: 1 };
    this.lastFetched = 0;
    this.cacheDuration = 24 * 60 * 60 * 1000; // 24 hours
    this.supportedCurrencies = ['USD', 'EUR', 'GBP', 'PKR', 'INR', 'AED', 'SAR', 'CAD', 'AUD'];
  }

  async initialize() {
    await this.fetchRates();
  }

  async fetchRates() {
    try {
      const response = await axios.get('https://api.frankfurter.dev/v2/rates?base=USD');
      console.log('Raw API Response from Frankfurter (preview):', Array.isArray(response.data) ? response.data.slice(0, 2) : response.data);
      
      if (Array.isArray(response.data)) {
        // Some currencies might not be provided by Frankfurter, include safe fallbacks
        const newRates = { USD: 1, PKR: 280, INR: 83, AED: 3.67, SAR: 3.75 };
        response.data.forEach(item => {
          newRates[item.quote] = item.rate;
        });
        this.rates = newRates;
        this.lastFetched = Date.now();
        logger.info('Currency rates updated from API');
      } else if (response.data && response.data.rates) {
        this.rates = { USD: 1, ...response.data.rates };
        this.lastFetched = Date.now();
        logger.info('Currency rates updated from API');
      } else {
        throw new Error('Unrecognized format from Frankfurter API');
      }
    } catch (error) {
      logger.error('Failed to fetch currency rates, using fallback values if available', error);
      // Fallback pseudo-rates in case API is down entirely
      if (Object.keys(this.rates).length <= 1) {
        this.rates = {
          USD: 1, EUR: 0.95, GBP: 0.81, PKR: 280, INR: 83, AED: 3.67, SAR: 3.75, CAD: 1.35, AUD: 1.52
        };
      }
    }
  }

  async getRates() {
    if (Date.now() - this.lastFetched > this.cacheDuration) {
      // Don't await here directly if we want to return immediately and update in background
      await this.fetchRates();
    }
    return this.supportedCurrencies.reduce((acc, code) => {
      acc[code] = this.rates[code] || 1;
      return acc;
    }, {});
  }

  async convertFromUSD(amountUSD, targetCurrency) {
    if (Date.now() - this.lastFetched > this.cacheDuration) {
      await this.fetchRates();
    }
    
    const rate = this.rates[targetCurrency.toUpperCase()] || 1;
    const convertedAmount = amountUSD * rate;
    
    // Currency symbols map
    const symbols = {
      USD: '$', EUR: '€', GBP: '£', PKR: 'Rs ', INR: '₹', 
      AED: 'AED ', SAR: 'SAR ', CAD: 'C$', AUD: 'A$'
    };
    
    return {
      amount: Math.round(convertedAmount * 100) / 100, // Round to 2 decimal places
      symbol: symbols[targetCurrency.toUpperCase()] || targetCurrency + ' ',
      code: targetCurrency.toUpperCase()
    };
  }
}

module.exports = new CurrencyService();
