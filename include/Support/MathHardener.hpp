#pragma once
#include <cmath>
#include <algorithm>

namespace Aegis::Support {
    class MathHardener {
        static constexpr double EPSILON = 1e-12;
    public:
        static double safe(double value, double default_val = 0.0) {
            if (std::isnan(value) || std::isinf(value)) return default_val;
            return value;
        }
        static double log_safe(double value) {
            value = std::max(EPSILON, value);
            return safe(std::log(value));
        }
        static double sqrt_safe(double value) {
            return safe(std::sqrt(std::max(0.0, value)));
        }
        static double div_safe(double num, double den, double default_val = 0.0) {
            if (std::abs(den) < EPSILON) return default_val;
            return safe(num / den);
        }
    };
}
