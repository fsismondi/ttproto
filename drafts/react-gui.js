// ############### Some parameters ###############

/*var baseUrl = 'http://127.0.0.1:2080';
var analyseUrl = '/api/v1/testcase_analyse';
var dissectUrl = '/api/v1/frames_dissect';
var getTestCasesUrl = '/api/v1/get_testcases';*/
var baseUrl = 'http://127.0.0.1:8000';
var analyseUrl = '/api/v1/testcase_analyse';
var dissectUrl = '/api/v1/frames_dissect';
var getTestCasesUrl = '/test_cases.json';


// ############### React code ###############

// A renderer for the radio buttons
var RadioButton = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {
		var selected = (this.props.currentAction == this.props.inputValue);
		return (
			<label className={ (selected) ? 'btn btn-info active' : 'btn btn-info' } onClick={this.props.switchAction} value={this.props.inputValue} >
				<input type="radio" checked={selected} id={this.props.inputValue} name={this.props.inputName} value={this.props.inputValue} onChange={function(){}} /> {this.props.inputText}
			</label>
		);
	}
});



// A renderer for the input groups
var InputGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// If addon on right
		if (this.props.textOnLeft) return (
			<div className="input-group">
				<span className="input-group-addon">{this.props.addonText}</span>
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} />
			</div>
		);

		// If addon on left
		else return (
			<div className="input-group">
				<input type={this.props.inputType} className="form-control" name={this.props.inputName} placeholder={this.props.inputPlaceholder} />
				<span className="input-group-addon">{this.props.addonText}</span>
			</div>
		);
	}
});



// A renderer for the select group
var SelectGroupBloc = React.createClass({

	/**
	 * Render function for InputGroupBloc
	 */
	render: function() {

		// Analyse action
		if (this.props.currentAction == 'analyse') {
			var optionInputName = 'testcase_id';
			var optionAddonText = 'Test case';

			// For the moment, only this part is done
			return (
				<div className="input-group">
					<span className="input-group-addon" data-toggle="tooltip" data-placement="left" title="Hey hi">{optionAddonText}</span>
					<select name="cars" className="form-control">
						{
							this.props.testCases.map(function(tc){
								return (
									<option value={tc[0]} data-toggle="tooltip" data-placement="left" title="Hey hi" >{tc[0]}</option>
								);
							})
						}
					</select>
				</div>
			);
		}

		// TODO: Dissect options
	}
});



// The FormBloc renderer
var FormBloc = React.createClass({

	/**
	 * Get the list of test cases from the server
	 */
	loadTestCases: function() {
		$.ajax({
			url: this.props.baseUrl + getTestCasesUrl,
			dataType: 'json',
			success: function(data) {
				this.setState({testCases: data});
			}.bind(this),
			error: function(xhr, status, err) {
				console.error(this.props.url, status, err.toString());
			}.bind(this)
		});
	},


	/**
	 * Handler for when the user change the action (dissect or analyse)
	 */
	switchAction: function(optionChoosed) {
		this.setState({action: optionChoosed.currentTarget.value});
	},


	/**
	 * Function thrown after the element is fully loaded
	 */
	componentDidMount: function() {
		this.loadTestCases();
	},


	/**
	 * Getter of the initial state for parameters
	 */
	getInitialState: function() {
		return {
			action: 'analyse',
			testCases: []
		};
	},


	/**
	 * Render function for FormBloc
	 */
	render: function() {

		// The things that will change in the view in function of the current action
		if (this.state.action == 'analyse') {
			var url = this.props.baseUrl + analyseUrl;
			var optionsTitle = 'Analysis options';
			var selectOptions = <SelectGroupBloc currentAction={this.state.action} testCases={this.state.testCases} />;
		} else {
			var url = this.props.baseUrl + dissectUrl;
			var optionsTitle = 'Dissection options';
			var selectOptions = null;
		}
		
		var fileTitle = 'Pcap field to ' + this.state.action;

		return (
			<form action={url} method="post" enctype="multipart/form-data">
				<div className="col-sm-6">
					<div className="page-header">
						<h1>{fileTitle}</h1>
					</div>
					<InputGroupBloc inputName="pcap" inputType="file" addonText="Enter your pcap file" textOnLeft={true} inputPlaceholder="" />
				</div>

				<div className="col-sm-6">
					<div className="page-header">
						<h1>{optionsTitle}</h1>
					</div>
					<InputGroupBloc inputName="frame-number" inputType="text" addonText="Frame number" textOnLeft={true} inputPlaceholder="Enter a frame number if only one wanted" />

					{selectOptions}

					<div style={{textAlign: 'center'}}>
						<div className="btn-group" data-toggle="buttons" >
							<RadioButton inputName="options" inputValue="analyse" inputText="Analyse" currentAction={this.state.action} switchAction={this.switchAction} />
							<RadioButton inputName="options" inputValue="dissect" inputText="Dissect" currentAction={this.state.action} switchAction={this.switchAction} />
						</div>
					</div>
				</div>

				<p style={{textAlign: 'center'}}>
					<input type="submit" value="Execute" className="btn btn-success centered-block" />
				</p>
			</form>
		);
	}
});


// The PcapUtility renderer
var PcapUtility = React.createClass({

	/**
	 * Render function for PcapForm
	 */
	render: function() {
		return (
			<div className="row">
				<FormBloc baseUrl={baseUrl} />
			</div>
		);
	}
});



ReactDOM.render(
	<PcapUtility />,
	document.getElementById('content')
);



// ############### Extern code ###############

// Activate bootstrap's tooltip
$(function () {
  $('[data-toggle="tooltip"]').tooltip()
});