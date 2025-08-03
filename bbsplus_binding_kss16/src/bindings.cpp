#include <pybind11/pybind11.h>
#include <array>
#include <mcl/bn.hpp>
namespace py = pybind11;
using namespace mcl::bn;

PYBIND11_MODULE(kss16core, m)
{
    initPairing(CurveKSS16);

    /* ---- G1 ---- */
    py::class_<G1>(m, "G1")
        .def(py::init<>())
        .def_static("generator", [](){ return getG1basePoint(); })
        .def("__add__", [](const G1& a, const G1& b){ return a + b; })
        .def("__mul__", [](const G1& P, const Fr& s){ return P * s; })
        .def("serialize", [](const G1& P){
            std::array<uint8_t,192> buf{};
            P.serialize(buf.data(), buf.size(), IoSerialize);
            return py::bytes(reinterpret_cast<char*>(buf.data()), buf.size());
        });

    /* ---- G2 ---- */
    py::class_<G2>(m, "G2")
        .def(py::init<>())
        .def_static("generator", [](){ return getG2basePoint(); })
        .def("__add__", [](const G2& a, const G2& b){ return a + b; })
        .def("__mul__", [](const G2& Q, const Fr& s){ return Q * s; });

    /* ---- GT ---- */
    py::class_<Fp12>(m, "GT")
        .def(py::init<>())
        .def("serialize", [](const Fp12& e){
            std::array<uint8_t,384> buf{};
            e.serialize(buf.data(), buf.size(), IoSerialize);
            return py::bytes(reinterpret_cast<char*>(buf.data()), buf.size());
        });

    /* ---- pairing ---- */
    m.def("pairing", [](const G1& P, const G2& Q){
        Fp12 e; pairing(e, P, Q);
        return e;
    });
}
