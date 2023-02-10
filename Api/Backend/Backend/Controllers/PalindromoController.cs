using Backend.Shared;
using Microsoft.AspNetCore.Mvc;

namespace Backend.Controllers
{
    [Route("Core/[controller]")]
    [ApiController]
    public class PalindromoController : Controller
    {

        [HttpGet]
        public ActionResult<IEnumerable<string>> Getpalindromo
        (string texto)
        {
            try
            {
                //var texto = texto.Split(" ", "-");
                var result = ListPalindrome(texto).OrderByDescending(o => o.Length);


                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest("Error al generar listado de palindomo");
            }
        }

        private List<string> ListPalindrome(string PalindromeString)
        {
            List<string> ListPalindrome = new List<string>();
            for (float index = 0; index < PalindromeString.Length; index += (float).5)
            {
                float palindromeNearestElementRadius = index - (int)index;
                while ((index + palindromeNearestElementRadius) < PalindromeString.Length
                    && (index - palindromeNearestElementRadius) >= 0
                    && PalindromeString[(int)(index - palindromeNearestElementRadius)]
                            == PalindromeString[(int)(index + palindromeNearestElementRadius)])
                {
                    var element = PalindromeString.Substring((int)(index - palindromeNearestElementRadius),
                                (int)(index + palindromeNearestElementRadius + 1) -
                                (int)(index - palindromeNearestElementRadius));

                    if (element.Length != 1)
                    {
                        ListPalindrome.Add(element);
                    }

                    palindromeNearestElementRadius++;
                }
            }
            return ListPalindrome;
        }
    }
}
