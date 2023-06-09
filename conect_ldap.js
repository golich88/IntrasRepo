var events = require('events');
var util = require('util');
var ldap = require('ldapjs');
var async = require('async');
var _ = require('underscore');
var bunyan = require('bunyan');
var Url = require('url');

var User = require('./models/user');
var Group = require('./models/group');
var RangeRetrievalSpecifierAttribute = require('./client/rangeretrievalspecifierattribute');

var isPasswordLoggingEnabled = false;
var maxOutputLength = 256;

var log = bunyan.createLogger({
  name: 'ActiveDirectory',
  streams: [
    { level: 'fatal',
      stream: process.stdout }
  ]
});

var defaultPageSize = 1000; // The maximum number of results that AD will return in a single call. Default=1000
var defaultAttributes, originalDefaultAttributes;
defaultAttributes = originalDefaultAttributes = {
  user: [ 
    'dn',
    'userPrincipalName', 'sAMAccountName', /*'objectSID',*/ 'mail',
    'lockoutTime', 'whenCreated', 'pwdLastSet', 'userAccountControl',
    'employeeID', 'sn', 'givenName', 'initials', 'cn', 'displayName',
    'comment', 'description' 
  ],
  group: [
    'dn', 'cn', 'description'
  ]
};

var defaultReferrals, originalDefaultReferrals;
defaultReferrals = originalDefaultReferrals = {
  enabled: false,
  // Active directory returns the following partitions as default referrals which we don't want to follow
  exclude: [
    'ldaps?://ForestDnsZones\\..*/.*',
    'ldaps?://DomainDnsZones\\..*/.*',
    'ldaps?://.*/CN=Configuration,.*'
  ]
};

// Precompile some common, frequently used regular expressions.
var re = {
  'isDistinguishedName': /(([^=]+=.+),?)+/gi,
  'isUserResult': /CN=Person,CN=Schema,CN=Configuration,.*/i,
  'isGroupResult': /CN=Group,CN=Schema,CN=Configuration,.*/i
};

/**
 * Agent for retrieving ActiveDirectory user & group information.
 *
 * @public
 * @constructor
 * @param {Object|String} url The url of the ldap server (i.e. ldap://domain.com). Optionally, all of the parameters can be specified as an object. { url: 'ldap://domain.com', baseDN: 'dc=domain,dc=com', username: 'admin@domain.com', password: 'supersecret', { referrals: { enabled: true }, attributes: { user: [ 'attributes to include in response' ], group: [ 'attributes to include in response' ] } } }. 'attributes' & 'referrals' parameter is optional and only necesary if overriding functionality.
 * @param {String} baseDN The default base container where all LDAP queries originate from. (i.e. dc=domain,dc=com)
 * @param {String} username The administrative username or dn of the user for retrieving user & group information. (i.e. Must be a DN or a userPrincipalName (email))
 * @param {String} password The administrative password of the specified user.
 * @param {Object} defaults Allow for default options to be overridden. { attributes: { user: [ 'attributes to include in response' ], group: [ 'attributes to include in response' ] } }
 * @returns {ActiveDirectory}
 */
var ActiveDirectory = function(url, baseDN, username, password, defaults) {
  if (this instanceof ActiveDirectory) {
    this.opts = {};
    if (typeof(url) === 'string') {
      this.opts.url = url;
      this.baseDN = baseDN;
      this.opts.bindDN = username;
      this.opts.bindCredentials = password;

      if (typeof((defaults || {}).entryParser) === 'function') {
        this.opts.entryParser = defaults.entryParser;
      }
    }
    else {
      this.opts = _.defaults({}, url);
      this.baseDN = this.opts.baseDN;

      if (! this.opts.bindDN) this.opts.bindDN = this.opts.username;
      if (! this.opts.bindCredentials) this.opts.bindCredentials = this.opts.password;

      if (this.opts.logging) {
        log = bunyan.createLogger(_.defaults({}, this.opts.logging));
        delete(this.opts.logging);
      }
    }

    defaultAttributes = _.extend({}, originalDefaultAttributes, (this.opts || {}).attributes || {}, (defaults || {}).attributes || {});
    defaultReferrals = _.extend({}, originalDefaultReferrals, (this.opts || {}).referrals || {}, (defaults || {}).referrals  || {});

    log.info('Using username/password (%s/%s) to bind to ActiveDirectory (%s).', this.opts.bindDN,
             isPasswordLoggingEnabled ? this.opts.bindCredentials : '********', this.opts.url);
    log.info('Referrals are %s', defaultReferrals.enabled ? 'enabled. Exclusions: '+JSON.stringify(defaultReferrals.exclude): 'disabled');
    log.info('Default user attributes: %j', defaultAttributes.user || []);
    log.info('Default group attributes: %j', defaultAttributes.group || []);

    // Enable connection pooling
    // TODO: To be disabled / removed in future release of ldapjs > 0.7.1
    if (typeof(this.opts.maxConnections) === 'undefined') {
      this.opts.maxConnections = 20;
    }
    events.EventEmitter.call(this);
  }
  else {
    return(new ActiveDirectory(url, baseDN, username, password, defaults));
  }
};
util.inherits(ActiveDirectory, events.EventEmitter);

/**
 * Expose ldapjs filters to avoid TypeErrors for filters
 * @static
 */
ActiveDirectory.filters = ldap.filters;

/**
 * Truncates the specified output to the specified length if exceeded.
 * @param {String} output The output to truncate if too long
 * @param {Number} [maxLength] The maximum length. If not specified, then the global value maxOutputLength is used.
 */
function truncateLogOutput(output, maxLength) {
  if (typeof(maxLength) === 'undefined') maxLength = maxOutputLength;
  if (! output) return(output);

  if (typeof(output) !== 'string') output = output.toString();
  var length = output.length;
  if ((! length) || (length < (maxLength + 3))) return(output);

  var prefix = Math.ceil((maxLength - 3)/2);
  var suffix = Math.floor((maxLength - 3)/2);
  return(output.slice(0, prefix)+ '...' +
    output.slice(length-suffix));
}

/**
 * Checks to see if there are any event emitters defined for the
 * specified event name.
 * @param {String} event The name of the event to inspect.
 * @returns {Boolean} True if there are events defined, false if otherwise.
 */
function hasEvents(event) {
  return(events.EventEmitter.listenerCount(this, event) > 0);
}

/**
 * Checks to see if the value is a distinguished name.
 *
 * @private
 * @param {String} value The value to check to see if it's a distinguished name.
 * @returns {Boolean}
 */
function isDistinguishedName(value) {
  log.trace('isDistinguishedName(%s)', value);
  if ((! value) || (value.length === 0)) return(false);
  re.isDistinguishedName.lastIndex = 0; // Reset the regular expression
  return(re.isDistinguishedName.test(value));
}

/**
 * Parses the distinguishedName (dn) to remove any invalid characters or to
 * properly escape the request.
 *
 * @private
 *   @param dn {String} The dn to parse.
 * @returns {String}
 */
function parseDistinguishedName(dn) {
  log.trace('parseDistinguishedName(%s)', dn);
  if (! dn) return(dn);

  dn = dn.replace(/"/g, '\\"');
  return(dn.replace('\\,', '\\\\,'));
}

/**
 * Gets the ActiveDirectory LDAP query string for a user search.
 *
 * @private
 * @param {String} username The samAccountName or userPrincipalName (email) of the user.
 * @returns {String}
 */
function getUserQueryFilter(username) {
  log.trace('getUserQueryFilter(%s)', username);
  var self = this;

  if (! username) return('(objectCategory=User)');
  if (isDistinguishedName.call(self, username)) {
    return('(&(objectCategory=User)(distinguishedName='+parseDistinguishedName(username)+'))');
  }

  return('(&(objectCategory=User)(|(sAMAccountName='+username+')(userPrincipalName='+username+')))');
}

/**
 * Gets a properly formatted LDAP compound filter. This is a very simple approach to ensure that the LDAP
 * compound filter is wrapped with an enclosing () if necessary. It does not handle parsing of an existing
 * compound ldap filter.
 * @param {String} filter The LDAP filter to inspect.
 * @returns {String}
 */
function getCompoundFilter(filter) {
  log.trace('getCompoundFilter(%s)', filter);

  if (! filter) return(false);
  if ((filter.charAt(0) === '(') && (filter.charAt(filter.length - 1) === ')')) {
    return(filter);
  }
  return('('+filter+')');
}

/**
 * Gets the ActiveDirectory LDAP query string for a group search.
 *
 * @private
 * @param {String} groupName The name of the group
 * @returns {String}
 */
function getGroupQueryFilter(groupName) {
  log.trace('getGroupQueryFilter(%s)', groupName);
  var self = this;

  if (! groupName) return('(objectCategory=Group)');
  if (isDistinguishedName.call(self, groupName)) {
    return('(&(objectCategory=Group)(distinguishedName='+parseDistinguishedName(groupName)+'))');
  }
  return('(&(objectCategory=Group)(cn='+groupName+'))');
}

/**
 * Checks to see if the LDAP result describes a group entry.
 * @param {Object} item The LDAP result to inspect.
 * @returns {Boolean}
 */
function isGroupResult(item) {
  log.trace('isGroupResult(%j)', item);

  if (! item) return(false);
  if (item.groupType) return(true);
  if (item.objectCategory) {
    re.isGroupResult.lastIndex = 0; // Reset the regular expression
    return(re.isGroupResult.test(item.objectCategory));
  }
  if ((item.objectClass) && (item.objectClass.length > 0)) {
    return(_.any(item.objectClass, function(c) { return(c.toLowerCase() === 'group'); }));
  }
  return(false);
}

/**
 * Checks to see if the LDAP result describes a user entry.
 * @param {Object} item The LDAP result to inspect.
 * @returns {Boolean}
 */
function isUserResult(item) {
  log.trace('isUserResult(%j)', item);

  if (! item) return(false);
  if (item.userPrincipalName) return(true);
  if (item.objectCategory) {
    re.isUserResult.lastIndex = 0; // Reset the regular expression
    return(re.isUserResult.test(item.objectCategory));
  }
  if ((item.objectClass) && (item.objectClass.length > 0)) {
    return(_.any(item.objectClass, function(c) { return(c.toLowerCase() === 'user'); }));
  }
  return(false);
}

/**
 * Factory to create the LDAP client object.
 *
 * @private
 * @param {String} url The url to use when creating the LDAP client.
 * @param {object} opts The optional LDAP client options.
 */
function createClient(url, opts) {
  // Attempt to get Url from this instance.
  url = url || this.url || (this.opts || {}).url || (opts || {}).url;
  if (! url) {
    throw 'No url specified for ActiveDirectory client.';
  }
  log.trace('createClient(%s)', url);

  var opts = getLdapClientOpts(_.defaults({}, { url: url }, opts, this.opts));
  log.debug('Creating ldapjs client for %s. Opts: %j', opts.url, _.omit(opts, 'url', 'bindDN', 'bindCredentials'));
  var client = ldap.createClient(opts);
  return(client);
}

/**
 * Checks to see if the specified referral or "chase" is allowed.
 * @param {String} referral The referral to inspect.
 * @returns {Boolean} True if the referral should be followed, false if otherwise.
 */
function isAllowedReferral(referral) {
  log.trace('isAllowedReferral(%j)', referral);
  if (! defaultReferrals.enabled) return(false);
  if (! referral) return(false);

  return(! _.any(defaultReferrals.exclude, function(exclusion) {
    var re = new RegExp(exclusion, "i");
    return(re.test(referral));
  }));
}

/**
 * From the list of options, retrieves the ldapjs specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapOpts(opts) {
  return(_.defaults({}, getLdapClientOpts(opts), getLdapSearchOpts(opts)));
}

/**
 * From the list of options, retrieves the ldapjs client specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapClientOpts(opts) {
  return(_.pick(opts || {},
    // Client
    'url',
    'host', 'port', 'secure', 'tlsOptions',
    'socketPath', 'log', 'timeout', 'idleTimeout',
    'reconnect', 'queue', 'queueSize', 'queueTimeout',
    'queueDisable', 'bindDN', 'bindCredentials',
    'maxConnections'
  ));
}

/**
 * From the list of options, retrieves the ldapjs search specific options.
 *
 * @param {Object} opts The opts to parse.
 * @returns {Object} The ldapjs opts.
 */
function getLdapSearchOpts(opts) {
  return(_.pick(opts || {},
    // Search
    'filter', 'scope', 'attributes', 'controls',
    'paged', 'sizeLimit', 'timeLimit', 'typesOnly',
    'derefAliases'
  ));
}

/**
 * Performs a search on the LDAP tree.
 * 
 * @private
 * @param {String} [baseDN] The optional base directory where the LDAP query is to originate from. If not specified, then starts at the root.
 * @param {Object} [opts] LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execure when completed. callback(err: {Object}, results: {Array[Object]}})
 */
function search(baseDN, opts, callback) {
  var self = this;

  if (typeof(opts) === 'function') {
    callback = opts;
    opts = baseDN;
    baseDN = undefined;
  }
  if (typeof(baseDN) === 'object') {
    opts = baseDN;
    baseDN = undefined;
  }
  opts || (opts = {});
  baseDN || (baseDN = opts.baseDN) || (baseDN = self.baseDN);
  log.trace('search(%s,%j)', baseDN, opts);

  var isDone = false;
  var pendingReferrals = [];
  var pendingRangeRetrievals = 0;
  var client = createClient.call(self, null, opts);
  client.on('error', onClientError);

  /**
   * Call to remove the specified referral client.
   * @param {Object} client The referral client to remove.
   */
  function removeReferral(client) {
    if (! client) return;

    client.unbind();
    var indexOf = pendingReferrals.indexOf(client);
    if (indexOf >= 0) {
      pendingReferrals.splice(indexOf, 1);
    }
  }

  /**
   * The default entry parser to use. Does not modifications.
   * @params {Object} entry The original / raw ldapjs entry to augment
   * @params {Function} callback The callback to execute when complete.
   */
  var entryParser = (opts || {}).entryParser || (self.opts || {}).entryParser || function onEntryParser(item, raw, callback) {
    callback(item);
  };

  /**
   * Occurs when a search entry is received. Cleans up the search entry and pushes it to the result set.
   * @param {Object} entry The entry received.
   */
  function onSearchEntry(entry) {
    log.trace('onSearchEntry(%j)', entry);
    var result = entry.object;
    delete result.controls; // Remove the controls array returned as part of the SearchEntry

    // Some attributes can have range attributes (paging). Execute the query
    // again to get additional items.
    pendingRangeRetrievals++;
    parseRangeAttributes.call(self, result, opts, function(err, item) {
      pendingRangeRetrievals--;

      if (err) item = entry.object;
      entryParser(item, entry.raw, function(item) {
        if (item) results.push(item);
        if ((! pendingRangeRetrievals) && (isDone)) {
          onSearchEnd();
        }
      });
    });
  }

  /**
   * Occurs when a search reference / referral is received. Follows the referral chase if
   * enabled.
   * @param {Object} ref The referral.
   */
  function onReferralChase(ref) {
    var index = 0;
    var referralUrl;
    // Loop over the referrals received.
    while (referralUrl = (ref.uris || [])[index++]) {
      if (isAllowedReferral(referralUrl)) {
        log.debug('Following LDAP referral chase at %s', referralUrl);
        var referralClient = createClient.call(self, referralUrl, opts);
        pendingReferrals.push(referralClient);

        var referral = Url.parse(referralUrl);
        var referralBaseDn = (referral.pathname || '/').substring(1);
        referralClient.search(referralBaseDn, getLdapOpts(opts), controls, function(err, res) {
          /**
           * Occurs when a error is encountered with the referral client.
           * @param {Object} err The error object or string.
           */
          function onReferralError(err) {
            log.error(err, '[%s] An error occurred chasing the LDAP referral on %s (%j)',
                     (err || {}).errno, referralBaseDn, opts);
            removeReferral(referralClient);
          }
          // If the referral chase / search failed, fail silently.
          if (err) {
            onReferralError(err);
            return;
          }

          res.on('searchEntry', onSearchEntry);
          res.on('searchReference', onReferralChase);
          res.on('error', onReferralError);
          res.on('end', function(result) {
            removeReferral(referralClient);
            onSearchEnd();
          });
        });
      }
    }
  }

  /**
   * Occurs when a client / search error occurs.
   * @param {Object} err The error object or string.
   * @param {Object} res The optional server response.
   */
  function onClientError(err, res) {
    if ((err || {}).name === 'SizeLimitExceededError') {
      onSearchEnd(res);
      return;
    }

    client.unbind();
    log.error(err, '[%s] An error occurred performing the requested LDAP search on %s (%j)',
              (err || {}).errno || 'UNKNOWN', baseDN, opts);
    if (callback) callback(err);
  }

  /**
   * Occurs when a search results have all been processed.
   * @param {Object} result
   */
  function onSearchEnd(result) {
    if ((! pendingRangeRetrievals) && (pendingReferrals.length <= 0)) {
      client.unbind();
      log.info('Active directory search (%s) for "%s" returned %d entries.',
               baseDN, truncateLogOutput(opts.filter),
               (results || []).length);
      if (callback) callback(null, results);
    }
  }

  var results = [];
  
  var controls = opts.controls || (opts.controls = []);
  // Add paging results control by default if not already added.
  if (!_.any(controls, function(control) { return(control instanceof ldap.PagedResultsControl); })) {
    log.debug('Adding PagedResultControl to search (%s) with filter "%s" for %j',
              baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
    controls.push(new ldap.PagedResultsControl({ value: { size: defaultPageSize } }));
  }
  if (opts.includeDeleted) {
    if (!_.any(controls, function(control) { return(control.type === '1.2.840.113556.1.4.417'); })) {
      log.debug('Adding ShowDeletedOidControl(1.2.840.113556.1.4.417) to search (%s) with filter "%s" for %j',
                baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
      controls.push(new ldap.Control({ type: '1.2.840.113556.1.4.417', criticality: true }));
    }
  }

  log.debug('Querying active directory (%s) with filter "%s" for %j',
            baseDN, truncateLogOutput(opts.filter), _.any(opts.attributes) ? opts.attributes : '[*]');
  client.search(baseDN, getLdapOpts(opts), controls, function onSearch(err, res) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    res.on('searchEntry', onSearchEntry);
    res.on('searchReference', onReferralChase);
    res.on('error', function(err) { onClientError(err, res); });
    res.on('end', function(result) {
      isDone = true; // Flag that the primary query is complete
      onSearchEnd(result);
    });
  });
}

/**
 * Handles any attributes that might have been returned with a range= specifier.
 *
 * @private
 * @param {Object} result The entry returned from the query.
 * @param {Object} opts The original LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, result: {Object}})
 */
function parseRangeAttributes(result, opts, callback) {
  log.trace('parseRangeAttributes(%j,%j)', result, opts);
  var self = this;

  // Check to see if any of the result attributes have range= attributes.
  // If not, return immediately.
  if (! RangeRetrievalSpecifierAttribute.prototype.hasRangeAttributes(result)) {
    callback(null, result);
    return;
  }

  // Parse the range attributes that were provided. If the range attributes are null
  // or indicate that the range is complete, return the result.
  var rangeAttributes = RangeRetrievalSpecifierAttribute.prototype.getRangeAttributes(result);
  if ((! rangeAttributes) || (rangeAttributes.length <= 0)) {
    callback(null, result);
    return;
  }

  // Parse each of the range attributes. Merge the range attributes into
  // the properly named property.
  var queryAttributes = [];
  _.each(rangeAttributes, function(rangeAttribute, index) {
    // Merge existing range into the properly named property.
    if (! result[rangeAttribute.attributeName]) result[rangeAttribute.attributeName] = [];
    Array.prototype.push.apply(result[rangeAttribute.attributeName], result[rangeAttribute.toString()]);
    delete(result[rangeAttribute.toString()]);

    // Build our ldap query attributes with the proper attribute;range= tags to
    // get the next sequence of data.
    var queryAttribute = rangeAttribute.next();
    if ((queryAttribute) && (! queryAttribute.isComplete())) {
      queryAttributes.push(queryAttribute.toString());
    }
  });

  // If we're at the end of the range (i.e. all items retrieved), return the result.
  if (queryAttributes.length <= 0) {
    log.debug('All attribute ranges %j retrieved for %s', rangeAttributes, result.dn);
    callback(null, result);
    return;
  }

  log.debug('Attribute range retrieval specifiers %j found for "%s". Next range: %j',
            rangeAttributes, result.dn, queryAttributes);
  // Execute the query again with the query attributes updated.
  opts = _.defaults({ filter: '(distinguishedName='+parseDistinguishedName(result.dn)+')',
                      attributes: queryAttributes }, opts);
  search.call(self, opts, function onSearch(err, results) {
    if (err) {
      callback(err);
      return;
    }

    // Should be only one result
    var item = (results || [])[0];
    for(var property in item) {
      if (item.hasOwnProperty(property)) {
        if (! result[property]) result[property] = [];
        if (_.isArray(result[property])) {
          Array.prototype.push.apply(result[property], item[property]);
        }
      }
    }
    callback(null, result);
  });
}

/**
 * Checks to see if any of the specified attributes are the wildcard
 * '*" attribute.
 * @private
 * @params {Array} attributes - The attributes to inspect.
 * @returns {Boolean}
 */
function shouldIncludeAllAttributes(attributes) {
  return((typeof(attributes) !== 'undefined') &&
         ((attributes.length === 0) ||
          _.any(attributes || [], function(attribute) {
           return(attribute === '*');
         }))
  );
}

/**
 * Gets the required ldap attributes for group related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 */
function getRequiredLdapAttributesForGroup(opts) {
  if (shouldIncludeAllAttributes((opts || {}).attributes)) {
    return([ ]);
  }
  return(_.union([ 'dn', 'objectCategory', 'groupType', 'cn' ], 
                 includeGroupMembershipFor(opts, 'group') ? [ 'member' ] : []));
}

/**
 * Gets the required ldap attributes for user related queries in order to
 * do recursive queries, etc.
 *
 * @private
 * @params {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 */
function getRequiredLdapAttributesForUser(opts) {
  if (shouldIncludeAllAttributes((opts || {}).attributes)) {
    return([ ]);
  }
  return(_.union([ 'dn', 'cn' ], 
                 includeGroupMembershipFor(opts, 'user') ? [ 'member' ] : []));
}

/**
 * Retrieves / merges the attributes for the query.
 */
function joinAttributes() {
  for (var index = 0, length = arguments.length; index < length; index++){
    if (shouldIncludeAllAttributes(arguments[index])) {
      return([ ]);
    }
  }
  return(_.union.apply(this, arguments));
}

/**
 * Picks only the requested attributes from the ldap result. If a wildcard or
 * empty result is specified, then all attributes are returned.
 * @private
 * @params {Object} result The ldap result
 * @params {Array} attributes The desired or wanted attributes
 * @returns {Object} A copy of the object with only the requested attributes
 */
function pickAttributes(result, attributes) {
  if (shouldIncludeAllAttributes(attributes)) {
    attributes = function() { 
      return(true); 
    };
  }
  return(_.pick(result, attributes));
}

/**
 * Gets all of the groups that the specified distinguishedName (DN) belongs to.
 * 
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} dn The distinguishedName (DN) to find membership of.
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, groups: {Array[Group]})
 */
function getGroupMembershipForDN(opts, dn, stack, callback) {
  var self = this;
   
  if (typeof(stack) === 'function') {
    callback = stack;
    stack = undefined;
  }
  if (typeof(dn) === 'function') {
    callback = dn;
    dn = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    stack = dn;
    dn = opts;
    opts = undefined;
  }
  log.trace('getGroupMembershipForDN(%j,%s,stack:%j)', opts, dn, (stack || []).length);

  // Ensure that a valid DN was provided. Otherwise abort the search.
  if (! dn) {
    var error = new Error('No distinguishedName (dn) specified for group membership retrieval.');
    log.error(error);
    if (hasEvents('error')) self.emit('error', error);
    return(callback(error));
  }

  //  Note: Microsoft provides a 'Transitive Filter' for querying nested groups.
  //        i.e. (member:1.2.840.113556.1.4.1941:=<userDistinguishedName>)
  //        However this filter is EXTREMELY slow. Recursively querying ActiveDirectory
  //        is typically 10x faster.
  opts = _.defaults(_.omit(opts || {}, 'filter', 'scope', 'attributes'), {
    filter: '(member='+parseDistinguishedName(dn)+')',
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || defaultAttributes.group, [ 'groupType' ])
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      callback(err);
      return;
    }

    var groups = [];
    async.forEach(results, function(group, asyncCallback) {
      // accumulates discovered groups
      if (typeof(stack) !== 'undefined') {
        if (!_.findWhere(stack, { cn: group.cn })) {
          stack.push(new Group(group));
        } else {
          // ignore groups already found
          return(asyncCallback());
        }

        _.each(stack,function(s) {
          if (!_.findWhere(groups, { cn: s.cn })) {
            groups.push(s);
          }
        });
      }

      if (isGroupResult(group)) {
        log.debug('Adding group "%s" to %s"', group.dn, dn);
        groups.push(new Group(group));

        // Get the groups that this group may be a member of.
        log.debug('Retrieving nested group membership for group "%s"', group.dn);
        getGroupMembershipForDN.call(self, opts, group.dn, groups, function(err, nestedGroups) {
          if (err) {
            asyncCallback(err);
            return;
          }

          nestedGroups = _.map(nestedGroups, function(nestedGroup) {
            if (isGroupResult(nestedGroup)) {
              return(new Group(nestedGroup));
            }
          });
          log.debug('Group "%s" which is a member of group "%s" has %d nested group(s). Nested: %j',
                    group.dn, dn, nestedGroups.length, _.map(nestedGroups, function(group) {
                     return(group.dn);
                   }));
          Array.prototype.push.apply(groups, nestedGroups);
          asyncCallback();
        });
      }
      else asyncCallback();
    }, function(err) {
       if (err) {
        callback(err);
        return;
      }

      // Remove the duplicates from the list.
      groups =  _.uniq(_.sortBy(groups, function(group) { return(group.cn || group.dn); }), false, function(group) {
        return(group.dn);
      });

      log.info('Group "%s" has %d group(s). Groups: %j', dn, groups.length, _.map(groups, function(group) {
         return(group.dn);
      }));
      callback(err, groups);
    });
  });
}

/**
 * For the specified filter, return the distinguishedName (dn) of all the matched entries.
 *
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @params {Object|String} filter The LDAP filter to execute. Optionally a custom LDAP query object can be specified. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, dns: {Array[String]})
 */
function getDistinguishedNames(opts, filter, callback) {
  var self = this;

  if (typeof(filter) === 'function') {
    callback = filter;
    filter = opts;
    opts = undefined;
  }
  if (typeof(opts) === 'string') {
    filter = opts;
    opts = undefined;
  }
  log.trace('getDistinguishedNames(%j,%j)', opts, filter);

  opts = _.defaults(_.omit(opts || {}, 'attributes'), {
    filter: filter,
    scope: 'sub',
    attributes: joinAttributes((opts || {}).attributes || [], [ 'dn' ])
  });
  search.call(self, opts, function(err, results) {
    if (err) {
      if (callback) callback(err);
      return;
    }

    // Extract just the DN from the results
    var dns =  _.map(results, function(result) {
      return(result.dn);
    });
    log.info('%d distinguishedName(s) found for LDAP query: "%s". Results: %j',
             results.length, truncateLogOutput(opts.filter), results);
    callback(null, dns);
  });
}

/**
 * Gets the distinguished name for the specified user (userPrincipalName/email or sAMAccountName).
 *
 * @private
 * @param {Object} [opts] Optional LDAP query string parameters to execute. { scope: '', filter: '', attributes: [ '', '', ... ], sizeLimit: 0, timelimit: 0 }
 * @param {String} username The name of the username to retrieve the distinguishedName (dn).
 * @param {Function} callback The callback to execute when completed. callback(err: {Object}, dn: {String})
 */
function getUserDistinguishedName(opts, username, callback) {
  var self = this;

  if (typeof(username) === 'function') {
    callback = username;
    username = opts;
    opts = undefined;
  }
  log.trace('getDistinguishedName(%j,%s)', opts, username);
