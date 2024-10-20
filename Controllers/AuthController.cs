using AuthService.DTO;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("/auth")]
    public class AuthController: ControllerBase
    {
        private readonly Services.AuthService _authService;
        
        public AuthController(Services.AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public IActionResult Register(RegisterDTO register)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                if (register.Password != register.ConfirmPassword)
                {
                    ModelState.AddModelError("MissMatch", "Password does not match");
                    return BadRequest(ModelState);
                }

                if (_authService.IsEmailRegistered(register.Email))
                {
                    ModelState.AddModelError("EmailRegistered", "Email already registered, please login!");
                    return Conflict(ModelState);
                }

                _authService.Register(register.Email, register.Password, register.Role);
                return Ok("User registered successfully");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }

        [HttpPost("login")]
        public IActionResult Login(LoginDTO login)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var tokenData = _authService.Login(login.Email, login.Password);
                if (tokenData == null)
                {
                    return Unauthorized("Invalid credentials");
                }

                return Ok(tokenData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
        
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken(RefreshTokenDTO newToken)
        {
            try
            {
                var tokenData = _authService.RefreshToken(newToken.Token, newToken.RefreshToken);
                if (tokenData == null)
                {
                    return Unauthorized("Invalid token or refresh token");
                }

                return Ok(tokenData);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
    }    
}

