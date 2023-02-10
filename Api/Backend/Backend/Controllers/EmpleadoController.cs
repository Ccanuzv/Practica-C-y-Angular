using Backend.Data;
using Backend.Modelo.Entity;
using Backend.Modelo.Repositories.IRepository;
using Backend.Modelo.Repositories.Repository;
using Backend.Modelo.ViewModels;
using Backend.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;

namespace Backend.Controllers
{
    [Authorize]
    [Route("Core/[controller]")]
    [ApiController]
    public class EmpleadoController : Controller
    {
        private readonly IEmpleadoRepository _empleadoRepository;
        private readonly ILogger<EmpleadoController> _logger;
        private readonly IConfiguration _config;
        private readonly PracticaDB _context;

        public EmpleadoController(IEmpleadoRepository empleadoRepository, ILogger<EmpleadoController> logger, IConfiguration config, PracticaDB context)
        {
            _empleadoRepository = empleadoRepository;
            _logger = logger;
            _config = config;
            _context = context;
        }

        [HttpPost]
        public ActionResult PostEmpleado(EmpleadoCrearViewModel model)
        {
            using (var transaction = _context.Database.BeginTransaction())
            {
                var usuariobusca = _empleadoRepository.GetAll().FirstOrDefault(w => w.EmpleadoDPI.Equals(model.DPI));
                //validad si hay otro nick igual
                if (usuariobusca != null)
                {
                    return Unauthorized("Acción invalida");
                }

                try
                {
                    Empleado empleado = new Empleado();
                    empleado.EmpleadoId = UiddGenetor.uidd();
                    empleado.EmpleadoNombre = model.Nombre;
                    empleado.EmpleadoDPI = model.DPI;
                    empleado.EmpleadoCantidadHijos = model.CantidadHijos;
                    empleado.EmpleadoSalario = model.Salario;
                    empleado.EmpleadoBonoDecreto = model.BonoDecreto;
                    empleado.EmpleadoFechaCreacion = DateTime.Now;
                    empleado.EmpleadoUsuarioId = ClaimUsuario.UsuarioId(HttpContext);
                    _empleadoRepository.Create(empleado);
                    transaction.Commit();

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                    transaction.Rollback();
                    return BadRequest("error en la creacion");
                }
            }
            return Ok(1);
        }

        [HttpGet]
        public ActionResult<PagedResult<EmpleadoViewModel>> GetEmpleado
            (
            string sortName = "Id",
            string sortOrder = "asc",
            int pageNumber = 1,
            int pageSize = Constantes.PAGE_SIZE,
            string? nombre = null)
        {
            try
            {
                int count = 0;
                var empleados = _empleadoRepository.GetAll().Select(
                    s => new EmpleadoViewModel
                    {
                        Id = s.EmpleadoId,
                        Nombre = s.EmpleadoNombre,
                        DPI = s.EmpleadoDPI,
                        CantidadHijos = s.EmpleadoCantidadHijos,
                        Salario = s.EmpleadoSalario,
                        BonoDecreto = s.EmpleadoBonoDecreto,
                        FechaCreacion = s.EmpleadoFechaCreacion,
                        UsuarioId = s.EmpleadoUsuarioId
                        
                    }); ;
                if (!string.IsNullOrEmpty(nombre))
                {
                    empleados = empleados.Where(s => s.Nombre.Contains(nombre));
                }

                count = empleados.Count();
                switch (sortName)
                {
                    case "Id":
                        empleados = sortOrder == "asc" ? empleados.OrderBy(d => d.Id) : empleados.OrderByDescending(d => d.Id);
                        break;
                    case "nombre":
                        empleados = sortOrder == "asc" ? empleados.OrderBy(d => d.Nombre) : empleados.OrderByDescending(d => d.Nombre);
                        break;
                    default:
                        empleados.OrderByDescending(d => d.Id);
                        break;
                }


                int page0 = (pageNumber - 1) * pageSize;
                empleados = empleados.Skip(page0).Take(pageSize);
                return new PagedResult<EmpleadoViewModel>(empleados, pageNumber, pageSize, count);

            }
            catch (Exception ex)
            {
                _logger.LogError($"Error al obtener rol {ex}");
                return BadRequest($"Error al obtener rol {ex}");
            }

        }

    }
    }
