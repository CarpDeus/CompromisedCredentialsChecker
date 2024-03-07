using RestSharp;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System;
using System.Security.Cryptography;
using System.Xml.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text.Json.Nodes;
using System.Linq;
using System.Text.RegularExpressions;

namespace CompromisedCredentialsChecker
{
    /// <summary>
    /// .NET package for V3 API of https://haveibeenpwned.com/
    /// </summary>
    public class Checker
    {
        static readonly string emptyJsonString = "{}";
        #region Helper Methods
        static string Hash(string input)
        {
#if NET8_0_OR_GREATER
            var hash = SHA1.HashData(Encoding.UTF8.GetBytes(input));
            var sb = new StringBuilder(hash.Length * 2);

            foreach (byte b in hash)
            {
                sb.Append(b.ToString("X2"));
            }

            return sb.ToString();
#else
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
#endif

        }
        /// <summary>
        /// Handler for all the errors that can be returned from the API
        /// </summary>
        /// <param name="ApiKey"></param>
        /// <param name="response"></param>
        /// <exception cref="HttpRequestException"></exception>
        private static void HandlePwnedApiErrors(string ApiKey, RestResponse response)
        {
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                string errorMessage;
#if NET8_0_OR_GREATER
                errorMessage = response.StatusCode switch
                {
                    System.Net.HttpStatusCode.Unauthorized => $"API {ApiKey} is not authorized",
                    System.Net.HttpStatusCode.Forbidden => $"User Agent Not supplied",
                    _ => $"Call returned {response.StatusCode} ({response.StatusDescription})",
                };
#else

 switch (response.StatusCode)
                {
                    case System.Net.HttpStatusCode.Unauthorized:
                        errorMessage = $"API {ApiKey} is not authorized"; break;
                    case System.Net.HttpStatusCode.Forbidden:
                        errorMessage = $"User Agent Not supplied"; break;
                    default: errorMessage = $"Call returned {response.StatusCode} ({response.StatusDescription})"; break;
                }
#endif
                throw new HttpRequestException(errorMessage);
            }
        }

        /// <summary>
        /// Common function to use the RestSharp library to call the HaveIBeenPwned API
        /// </summary>
        /// <param name="ApiKey"></param>
        /// <param name="UserAgent"></param>
        /// <param name="pwnedURI"></param>
        /// <returns></returns>
        /// <exception cref="HttpRequestException"></exception>
        private static RestResponse CallPwnedRestApi(string ApiKey, string UserAgent, string pwnedURI)
        {
            var client = new RestClient(pwnedURI);
            var request = new RestRequest
            {
                Method = Method.Get,
                RequestFormat = DataFormat.Json
            };
            request.AddHeader("hibp-api-key", ApiKey);
            if (string.IsNullOrEmpty(UserAgent))
            {
                throw new HttpRequestException($"User Agent Not supplied");
            }
            request.AddHeader("user-agent", UserAgent);
            var response = client.Get(request);
            return response;
        }

        /// <summary>
        ///  Deserialize Json to an object
        /// </summary>
        /// <typeparam name="T">Type of object to be returned</typeparam>
        /// <param name="Json"></param>
        /// <returns></returns>
        private static T DeserializeJSON<T>(string Json) where T : class
        {
            if (string.IsNullOrEmpty(Json) || Json == "{}" || Json == "[]")
            {
                return null;
            }
            else
            {
#if NET8_0_OR_GREATER
                return System.Text.Json.JsonSerializer.Deserialize<T>(Json);
#else
            return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(Json);
#endif
            }
        }

        private static void ParsePassword(string PlainPassword, out string sha1PasswordRange, out string sha1PasswordSuffix)
        {
            // The API only takes the first 5 of the SHA1 hashed password and only returns
            // the last part of the SHA1 hashed password
            string sha1Password = Hash(PlainPassword);
#if NET8_0_OR_GREATER
            sha1PasswordRange = sha1Password[..5];
            sha1PasswordSuffix = sha1Password[5..];
#else
            sha1PasswordRange = sha1Password.Substring(0, 5);
            sha1PasswordSuffix = sha1Password.Substring(5);
#endif
        }
        #endregion

        /// <summary>
        /// Determine if the password has been found in a hack, returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="PlainPassword">The password to be checked</param>
        /// <returns>Raw result from the API</returns>
        public static string PasswordCheckResults(string ApiKey, string UserAgent, string PlainPassword)
        {
            string sha1PasswordRange;
            string sha1PasswordSuffix;
            ParsePassword(PlainPassword, out sha1PasswordRange, out sha1PasswordSuffix);
            string pwnedURI = $"https://api.pwnedpasswords.com/range/{sha1PasswordRange}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);
            return response.Content;

        }

        /// <summary>
        /// Determine if the password has been found in a hack
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="PlainPassword">The password to be checked</param>
        /// <returns>The number of data breaches the password has been found in</returns>
        public static Int64 PasswordCheck(string ApiKey, string UserAgent, string PlainPassword)
        {
            string sha1PasswordRange;
            string sha1PasswordSuffix;
            ParsePassword(PlainPassword, out sha1PasswordRange, out sha1PasswordSuffix);
            string fromApi = PasswordCheckResults(ApiKey, UserAgent, PlainPassword);
            long retVal;
            // Check to see if the requested password is in the returned list
            if (!fromApi.Contains(sha1PasswordSuffix))
            { return 0; }
            else
            {
                int hashLocation = fromApi.IndexOf(sha1PasswordSuffix);
                int eolLocation = fromApi.IndexOf('\r', hashLocation);
                int colonLocation = fromApi.IndexOf(':', hashLocation);
                string count = fromApi.Substring(colonLocation + 1, eolLocation - colonLocation);
                Int64.TryParse(count, out retVal);
            }
            return retVal;

        }


        /// <summary>
        /// Determine all the breaches the email address has been involved in. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="EmailAddress">Email address to be searched for</param>
        /// <param name="NamesOnly">If true, only the names of the breaches are returned. If False, all breach data returned. Default is true and returns all information about the breaches</param>
        /// <param name="DomainFilter">If supplied, only breaches against the domain are returned.</param>
        /// <param name="ExcludeUnverified">If true, this excludes breaches that have been flagged as "unverified". By default, both verified and unverified breaches are returned if this parameter not included or passed in as true</param>
        /// <returns>Raw result from the API</returns>
        public static string GetBreachesForEmailAddressResult(string ApiKey, string UserAgent, string EmailAddress, bool NamesOnly = true, string DomainFilter = "", bool ExcludeUnverified = false)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/breachedaccount/{EmailAddress}";
            bool hasParameters = false;
            if (!NamesOnly)
            {
                pwnedURI += "?truncateResponse=false";
                hasParameters = true;
            }
            if (!string.IsNullOrEmpty(DomainFilter))
            {
                if (hasParameters)
                {
                    pwnedURI += "&";
                }
                else
                {
                    pwnedURI += "?";
                    hasParameters = true;
                }
                pwnedURI += $"Domain={DomainFilter}";
            }
            if (ExcludeUnverified)
            {
                if (hasParameters)
                {
                    pwnedURI += "&";
                }
                else
                {
                    pwnedURI += "?";
                    hasParameters = true;
                }
                pwnedURI += "IncludeUnverified=false";
            }

            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }

        /// <summary>
        /// Determine all the breaches the email address has been involved in.
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="EmailAddress">Email address to be searched for</param>
        /// <param name="NamesOnly">If true, only the names of the breaches are returned. If False, all breach data returned. Default is true and returns all information about the breaches</param>
        /// <param name="DomainFilter">If supplied, only breaches against the domain are returned.</param>
        /// <param name="ExcludeUnverified">If true, this excludes breaches that have been flagged as "unverified". By default, both verified and unverified breaches are returned if this parameter not included or passed in as true</param>
        /// <returns>Array of breaches that the email address has been involved in. If the number of breaches is 0 (zero) than the email address has not been involved in a breach</returns>
        public static List<HIBPBreach> GetBreachesForEmailAddress(string ApiKey, string UserAgent, string EmailAddress, bool NamesOnly = true, string DomainFilter = "", bool ExcludeUnverified = false)
        {

            return DeserializeJSON<List<HIBPBreach>>(GetBreachesForEmailAddressResult(ApiKey, UserAgent, EmailAddress, NamesOnly, DomainFilter));
        }


        /// <summary>
        /// Determine all the breaches for email addresses for a specific domain. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="Domain">Email address to be searched for</param>
        /// <returns>Raw result from the API</returns>
        public static string GetBreachedEmailsForDomainResult(string ApiKey, string UserAgent, string Domain)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/breacheddomain/{Domain}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            //var parsed= JsonConvert.DeserializeObject<JObject>(response.Content);
            //var parsed2 = DeserializeJSON<JsonObject>(response.Content);
            //var result = new List<HIBPDomainBreachedEmails>();

            return response.Content;
        }

        /// <summary>
        /// Determine all the breaches for email addresses for a specific domain.
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="Domain">Email address to be searched for</param>
        /// <returns>All email addresses on a given domain and the breaches they've appeared in can be returned via the domain search API. Only domains that have been successfully added to the domain search dashboard after verifying control can be searched. </returns>
        public static List<HIBPDomainBreachedEmails> GetBreachedEmailsForDomain(string ApiKey, string UserAgent, string Domain)
        {
            List<HIBPDomainBreachedEmails> retVal = new List<HIBPDomainBreachedEmails>();
            string results = GetBreachedEmailsForDomainResult(ApiKey, UserAgent, Domain);
            // First split into array of strings
            if(results == emptyJsonString)
            {
                return retVal;
            }
            else
            {
                results = results.Replace("{", "").Replace("}", "");
                string[] splitResults = results.Split(']');
                foreach (string s in splitResults)
                {
                    string[] splitEmails = s.Split(':');
                    if(splitEmails.Length < 2)
                    {
                        continue;
                    }
                    List<string> breaches = new List<string>();
                    foreach(string breach in splitEmails[1].Split(','))
                    {
                        breaches.Add(breach.Replace("\"", "").Replace("[", "").Replace("]", ""));
                    }
                    
                    retVal.Add(new HIBPDomainBreachedEmails() { Alias= splitEmails[0].Replace("\"", ""), Breaches = breaches.ToArray() });
                }
                return retVal;
            }
        }


        /// <summary>
        /// Get a list of all domains that the API has subscribed to for breach notifications. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Raw result from the API</returns>
        public static string GetSubscribedDomainsResult(string ApiKey, string UserAgent)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/subscribeddomains";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }

        /// <summary>
        /// Get a list of all domains that the API has subscribed to for breach notifications
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>List of all domains that the API has subscribed to for breach notifications</returns>
        public static List<HIBPSubscribedDomain> GetSubscribedDomains(string ApiKey, string UserAgent)
        {
            return DeserializeJSON<List<HIBPSubscribedDomain>>(GetSubscribedDomainsResult(ApiKey, UserAgent));
        }


        /// <summary>
        /// Get a list of all of the breaches in the system. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="DomainFilter">If supplied, only breaches against the domain are returned.</param>
        /// <param name="IsSpamList">Filters the result set to only breaches that either are or are not flagged as a spam list.</param>
        /// <returns>Raw result from the API</returns>
        public static string GetAllBreachesResult(string ApiKey, string UserAgent, string DomainFilter = "", bool IsSpamList = false)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/breaches";
            bool hasParameters = false;

            if (string.IsNullOrEmpty(DomainFilter))
            {
                if (hasParameters)
                {
                    pwnedURI += "&";
                }
                else
                {
                    pwnedURI += "?";
                    hasParameters = true;
                }
                pwnedURI += $"Domain={DomainFilter}";
            }
            if (IsSpamList)
            {
                if (hasParameters)
                {
                    pwnedURI += "&";
                }
                else
                {
                    pwnedURI += "?";
                    hasParameters = true;
                }
                pwnedURI += "IsSpamList=false";
            }

            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }

        /// <summary>
        /// Get a list of all of the breaches in the system
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="DomainFilter">If supplied, only breaches against the domain are returned.</param>
        /// <param name="IsSpamList">Filters the result set to only breaches that either are or are not flagged as a spam list.</param>
        /// <returns>List of all of the breaches in the system</returns>
        public static List<HIBPBreach> GetAllBreaches(string ApiKey, string UserAgent, string DomainFilter = "", bool IsSpamList = false)
        {

            return DeserializeJSON<List<HIBPBreach>>(GetAllBreachesResult(ApiKey, UserAgent, DomainFilter, IsSpamList));
        }


        /// <summary>
        /// Get a breach by name. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="BreachName">Name of the breach from the list of breaches</param>
        /// <returns>Raw result from the API</returns>
        public static string GetSingleBreachedSiteByNameResult(string ApiKey, string UserAgent, string BreachName)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/breach/{BreachName}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }


        /// <summary>
        /// Get a breach by name
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="BreachName">Name of the breach from the list of breaches</param>
        /// <returns>Breach details</returns>
        public static HIBPBreach GetSingleBreachedSiteByName(string ApiKey, string UserAgent, string BreachName)
        {

            return DeserializeJSON<HIBPBreach>(GetSingleBreachedSiteByNameResult(ApiKey, UserAgent, BreachName));
        }


        /// <summary>
        /// Get the most recently added breach
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Raw result from the API</returns>
        public static string GetMostRecentBreachAddedResult(string ApiKey, string UserAgent)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/latestbreach";

            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }

        /// <summary>
        /// Get the most recently added breach
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Most recent breach details</returns>
        public static HIBPBreach GetMostRecentBreachAdded(string ApiKey, string UserAgent)
        {
            return DeserializeJSON<HIBPBreach>(GetMostRecentBreachAddedResult(ApiKey, UserAgent));
        }

        /// <summary>
        /// Get all of the data classes in the system. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Raw result from the API</returns>
        public static string GetAllDataClassesResult(string ApiKey, string UserAgent)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/dataclasses";

            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return (response.Content);
        }

        /// <summary>
        /// Get all of the data classes in the system
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>List of all of the data classes in the system</returns>
        public static List<string> GetAllDataClasses(string ApiKey, string UserAgent)
        {
            return DeserializeJSON<List<string>>(GetAllDataClassesResult(ApiKey, UserAgent));
        }

        /// <summary>
        /// Check for pastes that have been found that include this email address. Returns API results as a string
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="emailAddress">Email address to be searched for</param>
        /// <returns>Raw result from the API</returns>
        public static string CheckPastesResult(string ApiKey, string UserAgent, string emailAddress)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/pasteaccount/{emailAddress}";
            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);
            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }

            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                HandlePwnedApiErrors(ApiKey, response);
            }
            return response.Content;

        }

        /// <summary>
        /// Check for pastes that have been found that include this email address
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <param name="emailAddress">Email address to be searched for</param>
        /// <returns>List of pastes with details</returns>
        public static HIBPPastes CheckPastes(string ApiKey, string UserAgent, string emailAddress)
        {
            return DeserializeJSON<HIBPPastes>(CheckPastesResult(ApiKey, UserAgent, emailAddress));
        }

        /// <summary>
        /// Get details of the current subscription. Returns API results as a string 
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Raw result from the API</returns>
        public static string GetSubscriptionStatusResult(string ApiKey, string UserAgent)
        {
            string pwnedURI = $"https://haveibeenpwned.com/api/v3/subscription/status";

            RestResponse response = CallPwnedRestApi(ApiKey, UserAgent, pwnedURI);

            //	Not found — the account could not be found and has therefore not been pwned
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                return emptyJsonString;
            }
            // Handle errors
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            { HandlePwnedApiErrors(ApiKey, response); }
            return response.Content;
        }

        /// <summary>
        /// Get details of the current subscription 
        /// </summary>
        /// <param name="ApiKey">API Key from https://haveibeenpwned.com/API/Key</param>
        /// <param name="UserAgent">String to indicate what application is using the API</param>
        /// <returns>Details of the current subscription</returns>
        public static HIBPSubscriptionStatus GetSubscriptionStatus(string ApiKey, string UserAgent)
        {

            return DeserializeJSON<HIBPSubscriptionStatus>(GetSubscriptionStatusResult(ApiKey, UserAgent));
        }

        
    }

    /// <summary>
    /// List of pastes with details
    /// </summary>
    public class HIBPPastes : List<HIBPPaste> { }

    /// <summary>
    /// Paste information from the HaveIBeenPwned API
    /// </summary>
    public class HIBPPaste
    {
        /// <summary>
        /// The paste service the record was retrieved from. Current values are: Pastebin, Pastie, Slexy, Ghostbin, QuickLeak, JustPaste, AdHocUrl, PermanentOptOut, OptOut
        /// </summary>
        public string Source { get; set; }
        /// <summary>
        /// The ID of the paste as it was given at the source service. Combined with the "Source" attribute, this can be used to resolve the URL of the paste.
        /// </summary>
        public string Id { get; set; }
        /// <summary>
        /// The title of the paste as observed on the source site. This may be null and if so will be omitted from the response.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// The date and time (precision to the second) that the paste was posted. This is taken directly from the paste site when this information is available but may be null if no date is published.
        /// </summary>
        public DateTime? Date { get; set; }
        /// <summary>
        /// The number of emails that were found when processing the paste. Emails are extracted by using the regular expression \b[a-zA-Z0-9\.\-_\+]+@[a-zA-Z0-9\.\-_]+\.[a-zA-Z]+\b
        /// </summary>
        public int EmailCount { get; set; }
    }

    /// <summary>
    /// Breach information from the HaveIBeenPwned API
    /// </summary>
    public class HIBPBreach
    {
        /// <summary>
        /// A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users (see the "Title" attribute instead).
        /// </summary>        /// 
        public string Name { get; set; }
        /// <summary>
        /// A descriptive title for the breach suitable for displaying to end users. It's unique across all breaches but individual values may change in the future (i.e. if another breach occurs against an organisation already in the system). If a stable value is required to reference the breach, refer to the "Name" attribute instead.
        /// </summary>
        public string Title { get; set; }
        /// <summary>
        /// The domain of the primary website the breach occurred on. This may be used for identifying other assets external systems may have for the site.
        /// </summary>
        public string Domain { get; set; }
        /// <summary>
        /// The date (with no time) the breach originally occurred on in ISO 8601 format. This is not always accurate — frequently breaches are discovered and reported long after the original incident. Use this attribute as a guide only.
        /// </summary>
        public DateTime BreachDate { get; set; }
        /// <summary>
        /// The date and time (precision to the minute) the breach was added to the system in ISO 8601 format.
        /// </summary>
        public DateTime AddedDate { get; set; }
        /// <summary>
        /// The date and time (precision to the minute) the breach was modified in ISO 8601 format. This will only differ from the AddedDate attribute if other attributes represented here are changed or data in the breach itself is changed (i.e. additional data is identified and loaded). It is always either equal to or greater then the AddedDate attribute, never less than.
        /// </summary>
        public DateTime ModifiedDate { get; set; }
        /// <summary>
        /// The total number of accounts loaded into the system. This is usually less than the total number reported by the media due to duplication or other data integrity issues in the source data.
        /// </summary>
        public int PwnCount { get; set; }
        /// <summary>
        /// Contains an overview of the breach represented in HTML markup. The description may include markup such as emphasis and strong tags as well as hyperlinks.
        /// </summary>
        public string Description { get; set; }
        /// <summary>
        /// A URI that specifies where a logo for the breached service can be found. Logos are always in PNG format.
        /// </summary>
        public string LogoPath { get; set; }
        /// <summary>
        /// This attribute describes the nature of the data compromised in the breach and contains an alphabetically ordered string array of impacted data classes.
        /// </summary>
        public List<string> DataClasses { get; set; }
        /// <summary>
        /// Indicates that the breach is considered unverified. An unverified breach may not have been hacked from the indicated website. An unverified breach is still loaded into HIBP when there's sufficient confidence that a significant portion of the data is legitimate.
        /// </summary>
        public bool IsVerified { get; set; }
        /// <summary>
        /// Indicates that the breach is considered unverified. An unverified breach may not have been hacked from the indicated website. An unverified breach is still loaded into HIBP when there's sufficient confidence that a significant portion of the data is legitimate.
        /// </summary>
        public bool IsFabricated { get; set; }
        /// <summary>
        /// Indicates if the breach is considered sensitive. The public API will not return any accounts for a breach flagged as sensitive.
        /// </summary>
        public bool IsSensitive { get; set; }
        /// <summary>
        /// 	Indicates if the breach has been retired. This data has been permanently removed and will not be returned by the API.
        /// </summary>
        public bool IsRetired { get; set; }
        /// <summary>
        /// 	Indicates if the breach has been retired. This data has been permanently removed and will not be returned by the API.
        /// </summary>
        public bool IsSpamList { get; set; }
        /// <summary>
        /// Indicates if the breach is sourced from malware. This flag has no impact on any other attributes, it merely flags that the data was sourced from a malware campaign rather than a security compromise of an online service.
        /// </summary>
        public bool IsMalware { get; set; }
        /// <summary>Indicates if the breach is subscription free. This flag has no impact on any other attributes, it is only used when running a domain search where a sufficiently sized subscription isn't present.</summary>
        public bool IsSubscriptionFree { get; set; }
    }

    /// <summary>
    /// A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users.
    /// </summary>
    public class HIBPBreachName
    {
        /// <summary>
        /// A Pascal-cased name representing the breach which is unique across all other breaches. This value never changes and may be used to name dependent assets (such as images) but should not be shown directly to end users.
        /// </summary>
        public string Name { get; set; }
    }

    /// <summary>
    /// Subscribed domain information from the HaveIBeenPwned API
    /// </summary>
    public class HIBPSubscribedDomain
    {
        /// <summary>
        /// The full domain name that has been successfully verified.
        /// </summary>
        public string DomainName { get; set; }
        /// <summary>
        /// The total number of breached email addresses found on the domain at last search (will be null if no searches yet performed).
        /// </summary>
        public int PwnCount { get; set; }
        /// <summary>
        /// The number of breached email addresses found on the domain at last search, excluding any breaches flagged as a spam list (will be null if no searches yet performed).
        /// </summary>
        public int PwnCountExcludingSpamLists { get; set; }
        /// <summary>
        /// The total number of breached email addresses found on the domain when the current subscription was taken out (will be null if no searches yet performed). This number ensures the domain remains searchable throughout the subscription period even if the volume of breached accounts grows beyond the subscription's scope.
        /// </summary>
        public object PwnCountExcludingSpamListsAtLastSubscriptionRenewal { get; set; }
        /// <summary>
        /// The date and time the current subscription ends in ISO 8601 format. The PwnCountExcludingSpamListsAtLastSubscriptionRenewal value is locked in until this time (will be null if there have been no subscriptions).
        /// </summary>
        public DateTime NextSubscriptionRenewal { get; set; }
    }

    /// <summary>
    /// SubscriptionStatus from the HaveIBeenPwned API
    /// </summary>
    public class HIBPSubscriptionStatus
    {
        /// <summary>
        /// The date and time the current subscription ends in ISO 8601 format.
        /// </summary>
        public DateTime SubscribedUntil { get; set; }
        /// <summary>
        /// The name representing the subscription being either "Pwned 1", "Pwned 2", "Pwned 3" or "Pwned 4".
        /// </summary>
        public string SubscriptionName { get; set; }
        /// <summary>
        /// A human readable sentence explaining the scope of the subscription.
        /// </summary>
        public string Description { get; set; }
        /// <summary>
        /// The size of the largest domain the subscription can search. This is expressed in the total number of breached accounts on the domain, excluding those that appear solely in spam list.
        /// </summary>
        public int DomainSearchMaxBreachedAccounts { get; set; }
        /// <summary>
        /// The rate limit in requests per minute. This applies to the rate the breach search by email address API can be requested.
        /// </summary>
        public int Rpm { get; set; }


    }

    /// <summary>
    /// Breached emails for domains controlled with the API
    /// </summary>
    public class HIBPDomainBreachedEmails
    {
        /// <summary>
        /// Alias for the breached email
        /// </summary>
        public string Alias { get; set; }
        /// <summary>
        /// Array of breaches that the email has been found in 
        /// </summary>
        public string[] Breaches { get; set; }
    }
}