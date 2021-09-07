using System.Linq;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RestSharp;
using System.Collections.Generic;

namespace C4.Orms.Encryption.Test
{
    [TestClass]
    public class HttpHeaderEncryption : TestBase
    {
        private List<HttpHeader> _headers = new List<HttpHeader>()
        {
            new HttpHeader("FieldList", "UserModel:Id|Email"),
            new HttpHeader("Predicate", "UserModel:Id|CompareValue|1|True|Equal"),
            new HttpHeader("Predicate", "UserModel:Email|CompareValue|test|True|Equal"),
            new HttpHeader("MaxItemsToReturn", "10"),
            new HttpHeader("SerializeDeafaultValue", "True"),
        };

        [TestMethod]
        public void Verify_Encrypted_Equals_Decrypted()
        {
            var decrypted = _headers.Encrypt().Decrypt();

            _headers.Should().Equal(decrypted);
        }

        [TestMethod]
        public void Verify_Header_Is_Encrypted()
        {
            _headers.FirstOrDefault().Encrypt().IsEncrypted().Should().BeTrue();
        }

        [TestMethod]
        public void Verify_Header_Encryption_Accepted()
        {
            _headers.FirstOrDefault().Encrypt().IsAcceptedEncryption().Should().BeTrue();
        }
    }
}