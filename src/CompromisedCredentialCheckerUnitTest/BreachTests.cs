namespace CompromisedCredentialsTestNet8
{
    [TestClass]
    public class BreachTests
    {
        readonly string userAgent = "azure-architect.com-UnitTests";
        
        [TestMethod]
        public void GetBreachesForEmailAddress()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            List<HIBPBreach> checkBreaches = Checker.GetBreachesForEmailAddress(apiKey, userAgent, Environment.GetEnvironmentVariable("HIBP_Email1"));
            Assert.IsTrue(checkBreaches.Count > 0);
        }

        [TestMethod]
        public void GetBreachesForEmailAddressFilterOutUnverified()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            string emailAddress = Environment.GetEnvironmentVariable("HIBP_Email1");
            List<HIBPBreach> checkBreaches = Checker.GetBreachesForEmailAddress(apiKey, userAgent, emailAddress);
            System.Threading.Thread.Sleep(20000);
            List<HIBPBreach> checkBreachesVerifiedOnly = Checker.GetBreachesForEmailAddress(apiKey, userAgent, emailAddress, false, "", true);
            if (checkBreachesVerifiedOnly == null) checkBreachesVerifiedOnly = new List<HIBPBreach>();
            Assert.IsTrue(checkBreaches.Count >= checkBreachesVerifiedOnly.Count);
        }
        [TestMethod]
        public void GetBreachesForEmailAddressFilterByDomain()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            string emailAddress = Environment.GetEnvironmentVariable("HIBP_Email2");
            List<HIBPBreach> checkBreaches = Checker.GetBreachesForEmailAddress(apiKey, userAgent, emailAddress, false);
            System.Threading.Thread.Sleep(20000);
            List<HIBPBreach> checkBreachesFilteredByDomain = Checker.GetBreachesForEmailAddress(apiKey, userAgent, emailAddress, true, checkBreaches[0].Domain);
            Assert.AreEqual((int)checkBreachesFilteredByDomain.Count, 1);
        }
    }
}