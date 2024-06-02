document.addEventListener('DOMContentLoaded', function() {
    let seconds = 0;
    let minutes = 0;
    let hours = 0;

    function updateTime() {
        seconds++;
        if (seconds >= 60) {
            seconds = 0;
            minutes++;
            if (minutes >= 60) {
                minutes = 0;
                hours++;
            }
        }

        const formattedTime = ${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')};
        document.getElementById('stopwatch').innerText = formattedTime;
    }

    setInterval(updateTime, 1000);
});
