namespace CompromisedCredentialsTestNet8
{
    [TestClass]
    public class PasteTests
    {
        //This needs set to run tests
        readonly string userAgent = "azure-architect.com-UnitTests";
        
        [TestMethod]
        public void PastesFound()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            HIBPPastes checkPastes = Checker.CheckPastes(apiKey, userAgent, Environment.GetEnvironmentVariable("HIBP_Email1"));
            Assert.IsTrue(checkPastes.Count > 0);
        }

        [TestMethod]
        public void NoPastesFound()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            HIBPPastes checkPastes = Checker.CheckPastes(apiKey, userAgent, $"{Guid.NewGuid()}@azure-architect.com");
            if(checkPastes == null) checkPastes = new HIBPPastes();
            Assert.AreEqual(checkPastes.Count, 0);
        }
    }
}