namespace CompromisedCredentialsTestNet8
{
    [TestClass]
    public class PasswordTests
    {
        //This needs set to run tests
        readonly string userAgent = "azure-architect.com-UnitTests";

        [TestMethod]
        public void PasswordCheckFound()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            long x =CompromisedCredentialsChecker.Checker.PasswordCheck(apiKey, userAgent, "123456");
            Assert.IsTrue(x > 0);
        }

        [TestMethod]
        public void PasswordCheckNotFound()
        {
            System.Threading.Thread.Sleep(20000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }
            long x = CompromisedCredentialsChecker.Checker.PasswordCheck(apiKey, userAgent, Guid.NewGuid().ToString());
            Assert.AreEqual(x, 0);
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException), "User Agent Not supplied")]
        public void PasswordCheckNoUserAgentSupplied()
        {
            System.Threading.Thread.Sleep(20000);
            System.Threading.Thread.Sleep(2000);
            string? apiKey = Environment.GetEnvironmentVariable("HIBP_API_KEY");
            if (string.IsNullOrEmpty(apiKey))
            {
                Assert.Fail("API Key not set");
            }

            CompromisedCredentialsChecker.Checker.PasswordCheck(apiKey, "", Guid.NewGuid().ToString());
        }

    }
}