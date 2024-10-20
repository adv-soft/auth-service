

using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthService.Configurations;
using AuthService.Models;
using Microsoft.IdentityModel.Tokens;
using RabbitMQ.Client;

namespace AuthService.Services
{
    public class AuthService
    {
        private readonly IConnection _connection;
        private readonly IModel _channel;
        private const string QueueName = "user_register_queue";
        private readonly AuthDbContext _context;
        private readonly IConfiguration _config;
        private readonly ConcurrentDictionary<string, string> _refreshTokens = new ConcurrentDictionary<string, string>();
        
        public AuthService(AuthDbContext dbContext, IConfiguration configuration)
        {
            var factory = new ConnectionFactory() { HostName = "localhost" };
            _connection = factory.CreateConnection();
            _channel = _connection.CreateModel();
            _channel.QueueDeclare(queue: QueueName,
                durable: false,
                exclusive: false,
                autoDelete: false,
                arguments: null);

            _context = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _config = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public void Register(string email, string password, string role)
        {
            string hashedPassword = HashPassword(password);
            string accessToken = GenerateJwtToken(email, role);
            
            var newUser = new AuthModel()
            {
                Password = hashedPassword,
                Email = email,
                AccessToken = accessToken,
                Role = role
            };

            _context.AuthModel.Add(newUser);
            _context.SaveChanges();
        }
        
        public bool IsEmailRegistered(string email)
        {
            return _context.AuthModel.Any(u => u.Email == email);
        }
        
        public object Login(string email, string password)
        {
            var user = AuthenticateUser(email, password);
           
            if (user == null)
                return null;
            
            var token = GenerateJwtToken(user.Email, user.Role);
            var refreshToken = GenerateRefreshToken();
            _refreshTokens[email] = refreshToken;
            return new { Token = token, RefreshToken = refreshToken };
        }
        
        public object RefreshToken(string token, string refreshToken)
        {
            var principal = GetPrincipalFromExpiredToken(token);
            var username = principal.Identity.Name;

            if (_refreshTokens.TryGetValue(username, out var storedRefreshToken) && storedRefreshToken == refreshToken)
            {
                var newToken = GenerateJwtToken(username, principal.FindFirst(ClaimTypes.Role)?.Value);
                var newRefreshToken = GenerateRefreshToken();
                _refreshTokens[username] = newRefreshToken;
                return new { Token = newToken, RefreshToken = newRefreshToken };
            }

            return null;
        }
        
        private AuthModel AuthenticateUser(string email, string password)
        {
            var hashedPassword = HashPassword(password);
            return _context.AuthModel.FirstOrDefault(u => u.Email == email && u.Password == hashedPassword);
        }
        
        private string HashPassword(string password)
        {
            using (var sha256 = SHA256.Create())
            {
                var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
            }
        }
        
        private string GenerateJwtToken(string email, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new System.Security.Claims.Claim(JwtRegisteredClaimNames.Sub, email),
                new System.Security.Claims.Claim("role", role)
            };

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(2),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
        
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

            if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
        
        public void Close()
        {
            _channel.Close();
            _connection.Close();
        }

    }
    
    
}

