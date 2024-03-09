using System.Collections.Generic;

namespace CompromisedCredentialsTestNet8
{
    [TestClass]
    public class SubscriptionTests
    {
        //This needs set to run tests
        readonly string userAgent = "azure-architect.com-UnitTests";

        [TestMethod]
        public void GetSubscriptionStatus()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            HIBPSubscriptionStatus subscriptionStatus = Checker.GetSubscriptionStatus(apiKey, userAgent);
            Assert.IsTrue(subscriptionStatus.Rpm > 0);
        }

        [TestMethod]
        public void GetSubscribedDomains()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            List <HIBPSubscribedDomain> subscribedDomains                = Checker.GetSubscribedDomains(apiKey, userAgent);
            Assert.IsTrue(subscribedDomains.Count> 0);
        }

        [TestMethod]
        public void GetBreachedEmailsForDomainResult()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            List <HIBPSubscribedDomain> c = Checker.GetSubscribedDomains(apiKey, userAgent);
            System.Threading.Thread.Sleep(2000);
            Checker.GetBreachedEmailsForDomainResult(apiKey, userAgent, c[0].DomainName);
            Assert.IsTrue(true);
        }

        [TestMethod]
        public void GetBreachedEmailsForDomain()
        {
         //   System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            //List<HIBPSubscribedDomain> c = Checker.GetSubscribedDomains(apiKey, userAgent);
            //System.Threading.Thread.Sleep(2000);
            //Checker.GetBreachedEmailsForDomainResult(apiKey, userAgent, c[0].DomainName);
            List<HIBPDomainBreachedEmails> breachedEmails= Checker.GetBreachedEmailsForDomain(apiKey, userAgent, "finsel.com"); 
            Assert.IsTrue(breachedEmails.Count >=0);
        }
    }
}