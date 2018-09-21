using AuthorizationServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security.OAuth;
using System.Threading.Tasks;
using System.Security.Claims;

namespace AuthorizationServer
{
    public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        // 1st Validate the client
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated(); //
        }

        // 2nd Add Claims
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            if (context.UserName == "Admin" && context.Password == "admin")
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, "admin"));
                identity.AddClaim(new Claim("username", "admin_acefrancis"));
                identity.AddClaim(new Claim(ClaimTypes.Name, "admin_Ace Francis Eli"));
                context.Validated(identity);
            }
            else if (context.UserName == "user" && context.Password == "user")
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, "Regular user"));
                identity.AddClaim(new Claim("username", "user_acefrancis"));
                identity.AddClaim(new Claim(ClaimTypes.Name, "user_Ace Francis Eli"));
                context.Validated(identity);
            }
            else
            {
                context.SetError("invalid grant", "Provided username and password is not correct");
                return;
            }
        }
    }
}