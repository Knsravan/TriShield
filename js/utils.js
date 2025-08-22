// A list of popular domains to check for typosquatting.
// Keep this list lowercase.
export const COMMON_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'paypal.com', 'ebay.com', 'reddit.com', 'office.com',
    'live.com', 'dropbox.com', 'stackoverflow.com', 'github.com', 'yahoo.com'
];

// A simple, local blacklist of known malicious hostnames.
export const LOCAL_BLACKLIST = [
    'malicious-example.com',
    'phishing-site.net',
    'get-free-stuff.org'
];

/**
 * Calculates the Levenshtein distance between two strings.
 * This measures the number of edits (insertions, deletions, substitutions)
 * needed to change one word into the other. A low distance (< 3)
 * between a link's domain and a common domain suggests typosquatting.
 * @param {string} s1 The first string.
 * @param {string} s2 The second string.
 * @returns {number} The Levenshtein distance.
 */
export function levenshteinDistance(s1, s2) {
    s1 = s1.toLowerCase();
    s2 = s2.toLowerCase();

    const costs = [];
    for (let i = 0; i <= s1.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= s2.length; j++) {
            if (i === 0) {
                costs[j] = j;
            } else {
                if (j > 0) {
                    let newValue = costs[j - 1];
                    if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
                        newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                    }
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
        }
        if (i > 0) costs[s2.length] = lastValue;
    }
    return costs[s2.length];
}